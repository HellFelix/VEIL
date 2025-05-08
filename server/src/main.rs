use pnet::packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};
use tokio_rustls::TlsAcceptor;

use encryption::get_tls_config;
use handshake::SessionRegistry;
use log::*;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};
use vpn_core::{
    logs::init_logger,
    network::{
        dhc::{self},
        SERVER_ADDR,
    },
    system::MTU_SIZE,
    Error, ErrorKind, Result,
};

use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex, RwLock,
    },
    task::JoinHandle,
    time::timeout,
};

mod echo;
mod encryption;
mod forwarding;
use forwarding::{Connection, RawSock, RawTcpSock, RawUdpSock, TcpConnection, UdpConnection};
mod handshake;

use echo::create_echo_reply;

use tokio_rustls::server::TlsStream;
type SecureStream = TlsStream<TcpStream>;

#[derive(Debug, Clone, Copy)]
#[toml_cfg::toml_config()]
pub struct ServerConfig {
    #[default(0)]
    pub address: u32,
    #[default(0)]
    pub port: u16,
}
impl ServerConfig {
    pub fn get_ipv4_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_bits(self.address)
    }
}

#[tokio::main]
async fn main() {
    match init().await {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }
}

async fn init() -> Result<()> {
    init_logger("server", "info", true);
    run_server().await?;
    Ok(())
}

async fn run_server() -> Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(get_tls_config()?));

    let server_socket = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), SERVER_CONFIG.port);
    let listener = TcpListener::bind(SocketAddr::V4(server_socket)).await?;
    let addr_pool = Arc::new(Mutex::new(dhc::AddrPool::create()));
    addr_pool.lock().await.claim(SERVER_ADDR)?;

    let session_registry = Arc::new(Mutex::new(SessionRegistry::create()));
    session_registry.lock().await.try_claim(0)?;

    loop {
        info!("Listening for clients");
        let (stream, peer_addr) = listener.accept().await?;
        info!("Found client at {peer_addr}");
        let acceptor = acceptor.clone();

        let addr_pool_ref = addr_pool.clone();
        let session_registry_ref = session_registry.clone();
        if let SocketAddr::V4(client_addr) = peer_addr {
            let mut addr_pool_lock = addr_pool_ref.lock().await;
            let mut session_registry_lock = session_registry_ref.lock().await;

            let mut stream = acceptor.accept(stream).await?;
            handshake::try_assign_address(
                &mut addr_pool_lock,
                &mut session_registry_lock,
                &mut stream,
                client_addr,
            )
            .await;
            let fut = async move {
                handle_client(stream).await?;

                Ok(()) as Result<()>
            };

            tokio::spawn(async move {
                if let Err(err) = fut.await {
                    error!("{:?}", err);
                }
            });
        }
    }
}

struct ClinetConn {
    pub channel: Sender<Vec<u8>>,
    pub out_link_handle: JoinHandle<()>,
    pub in_link_handle: JoinHandle<()>,
}

async fn handle_client(stream: SecureStream) -> Result<()> {
    let conns: Arc<RwLock<HashMap<ConnIdent, ClinetConn>>> = Arc::new(RwLock::new(HashMap::new()));

    let (mut tls_reader, mut tls_writer) = split(stream);
    let (in_sender, mut in_receiver) = channel(100);

    tokio::spawn(async move {
        info!("Forwarder running");
        let mut buf = [0u8; MTU_SIZE];
        loop {
            let size = tls_reader.read(&mut buf).await.unwrap();
            info!("Got packet from TLS");
            let (conn_ident, protocol, packet) = process_packet(&buf[..size]).unwrap();

            let mut conns_lock = conns.write().await;
            if let Some(conn) = conns_lock.get(&conn_ident) {
                info!("Found existing connection");
                conn.channel.send(buf[..size].to_owned()).await.unwrap();
            } else {
                info!("Found new connection");
                let (out_sender, out_receiver) = channel(10);
                out_sender.send(buf[..size].to_owned()).await.unwrap();

                let link_send = in_sender.clone();
                let link_handles = match protocol {
                    SupportedProtocol::Tcp => {
                        init_links::<RawTcpSock, TcpPacket, TcpConnection>(
                            out_receiver,
                            link_send,
                            &packet,
                            conn_ident,
                            Arc::clone(&conns),
                        )
                        .await
                    }
                    SupportedProtocol::Udp => {
                        init_links::<RawUdpSock, UdpPacket, UdpConnection>(
                            out_receiver,
                            link_send,
                            &packet,
                            conn_ident,
                            Arc::clone(&conns),
                        )
                        .await
                    }
                };

                info!("Lock is ready");
                conns_lock.insert(
                    conn_ident,
                    ClinetConn {
                        channel: out_sender,
                        out_link_handle: link_handles.0,
                        in_link_handle: link_handles.1,
                    },
                );
                info!("Finished Writing");
            }
        }
    });

    tokio::spawn(async move {
        info!("Responder running");
        while let Some(response) = in_receiver.recv().await {
            info!("Responder got response {response:?}");
            tls_writer.write_all(&response).await.unwrap();
        }
        info!("Responder done");
    });
    Ok(())
}

async fn shutdown_conn(conn_ident: ConnIdent, conns: Arc<RwLock<HashMap<ConnIdent, ClinetConn>>>) {
    if let Some(conn) = conns.read().await.get(&conn_ident) {
        info!("Sutting down!");
        conn.out_link_handle.abort();
        conn.in_link_handle.abort();
    }

    conns.write().await.remove(&conn_ident);
}

async fn init_links<S, P, C>(
    mut out_receiver: Receiver<Vec<u8>>,
    in_sender: Sender<Vec<u8>>,
    packet: &Ipv4Packet<'_>,
    conn_ident: ConnIdent,
    conns: Arc<RwLock<HashMap<ConnIdent, ClinetConn>>>,
) -> (JoinHandle<()>, JoinHandle<()>)
where
    S: RawSock,
    P: Packet,
    C: Connection<S, P> + 'static,
{
    let mut conn = create_conn::<S, P, C>(packet);

    let out_link_handle = tokio::spawn(async move {
        info!("Out-link running");
        loop {
            match timeout(Duration::from_secs(1), out_receiver.recv()).await {
                Ok(Some(mut packet)) => {
                    info!("Forwarding...");
                    conn.send_to_remote_host(&mut packet).unwrap();
                }
                _ => {
                    info!("Timout reached");
                    shutdown_conn(conn_ident, conns).await;
                    break;
                }
            }
        }
    });

    let in_link_handle = tokio::spawn(async move {
        loop {
            match tokio::task::spawn_blocking(move || conn.recv_from_remote_host())
                .await
                .unwrap()
            {
                Ok(res) => {
                    info!("In-link sending");
                    in_sender.send(res).await.unwrap();
                }
                Err(e) => {
                    error!("{e}");
                }
            }
        }
    });

    (out_link_handle, in_link_handle)
}

fn process_packet(buf: &[u8]) -> Option<(ConnIdent, SupportedProtocol, Ipv4Packet)> {
    let packet = Ipv4Packet::new(buf)?;
    let mut res = ConnIdent {
        dst_addr: packet.get_destination(),
        proto: packet.get_next_level_protocol(),
        eph_port: None,
        dst_port: None,
    };
    let protocol = match packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            get_ident_tcp(TcpPacket::new(packet.payload())?, &mut res);
            SupportedProtocol::Tcp
        }
        IpNextHeaderProtocols::Udp => {
            get_ident_udp(UdpPacket::new(packet.payload())?, &mut res);
            SupportedProtocol::Udp
        }
        _ => {
            return None;
        }
    };

    return Some((res, protocol, packet));
}

fn create_conn<S, P, C>(packet: &Ipv4Packet) -> C
where
    S: RawSock,
    P: Packet,
    C: Connection<S, P>,
{
    C::create_from_packet(packet)
}

fn get_ident_tcp(packet: TcpPacket, conn_ident: &mut ConnIdent) {
    conn_ident.eph_port = Some(packet.get_source());
    conn_ident.dst_port = Some(packet.get_destination());
}
fn get_ident_udp(packet: UdpPacket, conn_ident: &mut ConnIdent) {
    conn_ident.eph_port = Some(packet.get_source());
    conn_ident.eph_port = Some(packet.get_destination());
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ConnIdent {
    dst_addr: Ipv4Addr,
    eph_port: Option<u16>,
    dst_port: Option<u16>,
    proto: IpNextHeaderProtocol,
}

enum SupportedProtocol {
    Tcp,
    Udp,
}
