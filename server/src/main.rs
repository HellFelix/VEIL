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
    time::{Duration, SystemTime},
};
use vpn_core::{
    logs::init_logger,
    network::{
        dhc::{self, DeAuthStage, SessionID},
        SERVER_ADDR,
    },
    system::MTU_SIZE,
    Result,
};

use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Handle,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex, RwLock,
    },
    task::{yield_now, JoinHandle},
    time::timeout,
};

mod echo;
mod encryption;
mod forwarding;
use forwarding::{
    Connection, IcmpConnection, LifeCycle, RawSock, RawTcpSock, RawUdpSock, SockStateType,
    StatefulSock, TcpConnection, TcpLifeCycle, UdpConnection, UdpLifeCycle,
};
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
            let (_addr, session_id) = handshake::try_assign_address(
                &mut addr_pool_lock,
                &mut session_registry_lock,
                &mut stream,
                client_addr,
            )
            .await
            .unwrap();
            let fut = async move {
                handle_client(stream, session_id).await?;

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

struct ClientConn {
    pub channel: Sender<Vec<u8>>,
    pub out_link_handle: JoinHandle<()>,
    pub in_link_handle: JoinHandle<()>,
}

async fn handle_client(stream: SecureStream, session_id: SessionID) -> Result<()> {
    let conns: Arc<RwLock<HashMap<ConnIdent, ClientConn>>> = Arc::new(RwLock::new(HashMap::new()));

    let (mut tls_reader, mut tls_writer) = split(stream);
    let (in_sender, mut in_receiver): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel(100);

    let _responder_handle = tokio::spawn(async move {
        info!("Responder running");
        while let Some(response) = in_receiver.recv().await {
            info!("Responder got response {response:?}");
            tls_writer.write_all(&response).await.unwrap();
            if let Some(DeAuthStage::Acknowledge(_)) = DeAuthStage::from_bytes(&response) {
                info!("Shutting down responder for session {session_id:#x}");
                break;
            }
        }
        info!("Responder done");
    });

    tokio::spawn(async move {
        info!("Forwarder running");
        let mut buf = [0u8; MTU_SIZE];
        'listener: loop {
            let size = tls_reader.read(&mut buf).await.unwrap();
            info!("Got packet from TLS");
            if let Some(stage) = DeAuthStage::from_bytes(&buf[..size]) {
                let deauth_advance = match stage {
                    DeAuthStage::Disconnect(id) => {
                        if session_id == id {
                            info!("Got disconnect instruction from session {session_id:#x}. Sending acknowledgement.");
                            DeAuthStage::Acknowledge(session_id)
                        } else {
                            DeAuthStage::Rejection
                        }
                    }
                    _ => {
                        warn!("Invalid DeAuth sequence. Rejecting");
                        DeAuthStage::Rejection
                    }
                };
                in_sender
                    .send(deauth_advance.to_bytes().unwrap())
                    .await
                    .unwrap();

                if let DeAuthStage::Acknowledge(_) = deauth_advance {
                    break 'listener;
                }
            }
            let (conn_ident, protocol, packet) = process_packet(&buf[..size]).unwrap();

            let mut conns_lock = conns.write().await;
            if let Some(conn) = conns_lock.get(&conn_ident) {
                info!("Found existing connection");
                conn.channel.send(buf[..size].to_owned()).await.unwrap();
            } else {
                info!("Found new connection");
                match protocol {
                    SupportedProtocol::Stateful(p) => {
                        let conn_comms =
                            setup_stateful(packet, in_sender.clone(), p, conn_ident, &conns)
                                .await
                                .unwrap();

                        info!("Lock is ready");
                        conns_lock.insert(conn_ident, conn_comms);
                        info!("Finished Writing");
                    }
                    SupportedProtocol::StateLess(p) => {
                        handle_stateless(packet, p, in_sender.clone()).await;
                    }
                }
            }
        }

        info!("Listener stopped. Cleaning up session {session_id:#x}");
        let mut conns_lock = conns.write().await;
        for (_conn_ident, conn) in conns_lock.iter() {
            conn.out_link_handle.abort();
            conn.in_link_handle.abort();
        }
        conns_lock.clear();
    });

    Ok(())
}

async fn setup_stateful(
    packet: Ipv4Packet<'_>,
    in_sender: Sender<Vec<u8>>,
    protocol: StatefulProtocol,
    conn_ident: ConnIdent,
    conns: &Arc<RwLock<HashMap<ConnIdent, ClientConn>>>,
) -> Result<ClientConn> {
    let (out_sender, out_receiver) = channel(10);
    out_sender.send(packet.packet().to_owned()).await.unwrap();

    let link_send = in_sender;
    let link_handles = match protocol {
        StatefulProtocol::Tcp => {
            init_links::<StatefulSock, RawTcpSock, TcpPacket, TcpConnection, TcpLifeCycle>(
                out_receiver,
                link_send,
                &packet,
                conn_ident,
                Arc::clone(conns),
            )
            .await
        }
        StatefulProtocol::Udp => {
            init_links::<StatefulSock, RawUdpSock, UdpPacket, UdpConnection, UdpLifeCycle>(
                out_receiver,
                link_send,
                &packet,
                conn_ident,
                Arc::clone(conns),
            )
            .await
        }
    }?;
    Ok(ClientConn {
        channel: out_sender,
        out_link_handle: link_handles.0,
        in_link_handle: link_handles.1,
    })
}

async fn handle_stateless(
    packet: Ipv4Packet<'_>,
    protocol: StatelessProtocol,
    in_sender: Sender<Vec<u8>>,
) {
    match protocol {
        StatelessProtocol::Icmp => handle_icmp(packet, in_sender).await,
    }
}

async fn handle_icmp(packet: Ipv4Packet<'_>, in_sender: Sender<Vec<u8>>) {
    if packet.get_destination() == SERVER_ADDR {
        in_sender
            .send(create_echo_reply(packet.packet()).unwrap())
            .await
            .unwrap();
    } else {
        let mut conn = IcmpConnection::create_from_packet(&packet).unwrap();
        let mut packet = packet.packet().to_owned();
        conn.send_to_remote_host(&mut packet).unwrap();

        tokio::spawn(async move {
            let res = tokio::task::spawn_blocking(move || conn.recv_from_remote_host().unwrap())
                .await
                .unwrap();

            in_sender.send(res).await.unwrap();
        });
    }
}

async fn shutdown_conn(conn_ident: ConnIdent, conns: &mut HashMap<ConnIdent, ClientConn>) {
    if let Some(conn) = conns.get(&conn_ident) {
        info!("Sutting down!");
        conn.out_link_handle.abort();
        conn.in_link_handle.abort();
    }

    conns.remove(&conn_ident);
}

async fn init_links<T, S, P, C, L>(
    mut out_receiver: Receiver<Vec<u8>>,
    in_sender: Sender<Vec<u8>>,
    packet: &Ipv4Packet<'_>,
    conn_ident: ConnIdent,
    conns: Arc<RwLock<HashMap<ConnIdent, ClientConn>>>,
) -> Result<(JoinHandle<()>, JoinHandle<()>)>
where
    L: LifeCycle,
    T: SockStateType<L>,
    P: Packet,
    S: RawSock<T, L>,
    C: Connection<T, S, P, L> + 'static,
{
    let mut conn = create_conn::<T, S, P, C, L>(packet)?;

    let out_link_handle = tokio::spawn(async move {
        info!("Out-link running");
        loop {
            match timeout(Duration::from_secs(1), out_receiver.recv()).await {
                Ok(Some(mut packet)) => {
                    info!("Forwarding... {packet:?}");
                    conn.send_to_remote_host(&mut packet).unwrap();
                }
                _ => {
                    info!("Timout reached");
                    shutdown_conn(conn_ident, &mut *conns.write().await).await;
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

    Ok((out_link_handle, in_link_handle))
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
            SupportedProtocol::Stateful(StatefulProtocol::Tcp)
        }
        IpNextHeaderProtocols::Udp => {
            get_ident_udp(UdpPacket::new(packet.payload())?, &mut res);
            SupportedProtocol::Stateful(StatefulProtocol::Udp)
        }
        IpNextHeaderProtocols::Icmp => SupportedProtocol::StateLess(StatelessProtocol::Icmp),
        _ => {
            return None;
        }
    };

    return Some((res, protocol, packet));
}

fn create_conn<T, S, P, C, L>(packet: &Ipv4Packet) -> Result<C>
where
    L: LifeCycle,
    T: SockStateType<L>,
    S: RawSock<T, L>,
    P: Packet,
    C: Connection<T, S, P, L>,
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
    Stateful(StatefulProtocol),
    StateLess(StatelessProtocol),
}

enum StatefulProtocol {
    Tcp,
    Udp,
}

enum StatelessProtocol {
    Icmp,
}
