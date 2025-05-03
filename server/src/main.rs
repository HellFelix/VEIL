use pnet::packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
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
};

mod echo;
mod encryption;
mod forwarding;
use forwarding::{Connection, RawSock, RawTcpSock, TcpConnection};
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

async fn handle_client(stream: SecureStream) -> Result<()> {
    let mut channels: HashMap<ConnIdent, Sender<Vec<u8>>> = HashMap::new();

    let (mut tls_reader, mut tls_writer) = split(stream);
    let (in_sender, mut in_receiver) = channel(100);

    tokio::spawn(async move {
        info!("Forwarder running");
        let mut buf = [0u8; MTU_SIZE];
        loop {
            let size = tls_reader.read(&mut buf).await.unwrap();
            let (conn_ident, protocol, packet) = process_packet(&buf[..size]).unwrap();

            if let Some(ch) = channels.get(&conn_ident) {
                info!("Found existing connection");
                ch.send(buf[..size].to_owned()).await.unwrap();
            } else {
                info!("Found new connection");
                let (out_sender, out_receiver) = channel(10);
                channels.insert(conn_ident, out_sender.clone());
                out_sender.send(buf[..size].to_owned()).await.unwrap();

                let link_send = in_sender.clone();
                match protocol {
                    SupportedProtocol::Tcp => {
                        init_links::<RawTcpSock, TcpConnection>(out_receiver, link_send, &packet)
                            .await
                    }
                }
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
    // let (out_sender, out_receiver) = channel::<&[u8]>(10);
    // let (in_sender, in_receiver) = channel::<&[u8]>(10);

    // let size = stream.read(&mut read_buf).await?;
    // info!("Got from client {:?}", &read_buf[..size]);
    //
    // match read_buf[9] {
    //     1 => IcmpConnection::init_from(&mut read_buf[..size], stream).await?,
    //     6 => TcpConnection::init_from(&mut read_buf[..size], stream).await?,
    //     17 => UdpConnection::init_from(&mut read_buf[..size], stream).await?,
    //     _ => {
    //         return Err(Error::new(
    //             ErrorKind::InvalidInput,
    //             format!("Unknown next protocol"),
    //         ))
    //     }
    // }
    //
    Ok(())
}

async fn init_links<S, C>(
    mut out_receiver: Receiver<Vec<u8>>,
    in_sender: Sender<Vec<u8>>,
    packet: &Ipv4Packet<'_>,
) where
    S: RawSock,
    C: Connection<S> + 'static,
{
    let mut conn = create_conn::<S, C>(packet);

    let out_fut = tokio::spawn(async move {
        info!("Out-link running");
        while let Some(mut packet) = out_receiver.recv().await {
            info!("Forwarding...");
            conn.send_to_remote_host(&mut packet).unwrap();
        }
    });

    let in_fut = tokio::spawn(async move {
        // let res = tokio::task::spawn_blocking(|| )
        //     .await
        //     .unwrap();
        // TODO: Make receiving non-blocking.
        loop {
            let res = tokio::task::spawn_blocking(move || conn.recv_from_remote_host().unwrap())
                .await
                .unwrap(); // This shouldn't block the task
            info!("In-link sending");
            in_sender.send(res).await.unwrap();
        }
    });

    // let (out_res, in_res) = tokio::join!(out_fut, in_fut);
    // out_res.unwrap();
    // in_res.unwrap();
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
        _ => {
            return None;
        }
    };

    return Some((res, protocol, packet));
}

fn create_conn<S, C>(packet: &Ipv4Packet) -> C
where
    S: RawSock,
    C: Connection<S>,
{
    C::create_from_packet(packet)
}

fn get_ident_tcp(packet: TcpPacket, conn_ident: &mut ConnIdent) {
    conn_ident.eph_port = Some(packet.get_source());
    conn_ident.dst_port = Some(packet.get_destination());
}

#[derive(PartialEq, Eq, Hash)]
struct ConnIdent {
    dst_addr: Ipv4Addr,
    eph_port: Option<u16>,
    dst_port: Option<u16>,
    proto: IpNextHeaderProtocol,
}

enum SupportedProtocol {
    Tcp,
}
