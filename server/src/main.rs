use libc::{
    in_addr, poll, pollfd, recvfrom, send, sendto, sockaddr_in, socket, AF_INET, AF_PACKET,
    ETH_P_ALL, IPPROTO_ICMP, IPPROTO_TCP, POLLIN, SOCK_RAW,
};
use pnet::packet::{
    icmp::{self, echo_request::MutableEchoRequestPacket, IcmpPacket, IcmpTypes},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{self, Ipv4Packet, MutableIpv4Packet},
    tcp::{self, MutableTcpPacket, TcpPacket},
    Packet,
};

use rand::{Rng, RngCore};
use tokio_rustls::TlsAcceptor;

use std::{ffi::c_void, ptr, thread::sleep, time::Duration};

use encryption::get_tls_config;
use handshake::SessionRegistry;
use log::*;
use std::{
    io::{self, Read, Write},
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
    sync::Mutex,
};

use tokio_rustls::server::TlsStream;

mod echo;
mod encryption;
mod handshake;

use echo::create_echo_reply;
type SecureStream = TlsStream<TcpStream>;
type SecureRead = ReadHalf<SecureStream>;
type SecureWrite = WriteHalf<SecureStream>;

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

    let server_socket = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8345);
    let listener = TcpListener::bind(SocketAddr::V4(server_socket)).await?;
    let addr_pool = Arc::new(Mutex::new(dhc::AddrPool::create()));
    addr_pool.lock().await.claim(SERVER_ADDR)?;

    let session_registry = Arc::new(Mutex::new(SessionRegistry::create()));
    session_registry.lock().await.try_claim(0)?;
    // let active_connections: Arc<Mutex<Vec<Box<dyn Connection>>>> = Arc::new(Mutex::new(vec![]));

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

const SUBNET_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 69);

async fn handle_client(mut stream: SecureStream) -> Result<()> {
    let mut read_buf = [0u8; MTU_SIZE];

    let size = stream.read(&mut read_buf).await?;
    info!("Got from client {:?}", &read_buf[..size]);

    if read_buf[9] == 1 {
        // ICMP
        loop {
            stream
                .write(&echo::create_echo_reply(&read_buf[..size]).unwrap())
                .await?;
            stream.read(&mut read_buf).await?;
        }
    } else if read_buf[9] == 6 {
        let host_ip = Ipv4Addr::new(read_buf[12], read_buf[13], read_buf[14], read_buf[15]);
        let conn =
            TcpConnection::send_init(RawTcpSock::init(host_ip), &mut read_buf[..size]).await?;

        let (tls_reader, tls_writer) = split(stream);

        let recv_handle = tokio::spawn(async move {
            info!("starting receiver");
            handle_recv(conn, tls_writer).await.unwrap();
        });

        let forward_handle = tokio::spawn(async move {
            info!("starting writer");
            handle_forward(conn, tls_reader).await.unwrap();
        });

        let (_recv_res, _forward_res) = tokio::join!(recv_handle, forward_handle);
    }

    Ok(())
}

async fn handle_recv(conn: TcpConnection, mut tls_writer: SecureWrite) -> Result<()> {
    info!("receiver running!");
    loop {
        let res = conn.recv_from_remote_host().await?;
        info!("Sending to client, {res:?}");
        tls_writer.write_all(&res).await?;
    }
}

async fn handle_forward(mut conn: TcpConnection, mut tls_reader: SecureRead) -> Result<()> {
    info!("forwarder running!");
    let mut buf = [0u8; MTU_SIZE];
    loop {
        let size = tls_reader.read(&mut buf).await?;

        info!("Forwarding");
        conn.send_to_remote_host(&mut buf[..size]).await?;
    }
}

trait Connection {
    async fn send_to_remote_host(&mut self, packet: &mut [u8]) -> Result<()>;
    async fn recv_from_remote_host(&self) -> Result<Vec<u8>>;
}

#[derive(Clone, Copy)]
struct TcpConnection {
    pub socket: RawTcpSock,
    pub self_addr: Ipv4Addr,
    pub peer_addr: Ipv4Addr,
}

impl Connection for TcpConnection {
    async fn send_to_remote_host(&mut self, packet: &mut [u8]) -> Result<()> {
        self.socket.spoof_send_cont(packet, self.self_addr)
    }
    async fn recv_from_remote_host(&self) -> Result<Vec<u8>> {
        self.socket.spoof_recv(self.peer_addr)
    }
}
impl TcpConnection {
    pub async fn send_init(mut socket: RawTcpSock, packet: &mut [u8]) -> Result<Self> {
        let peer_addr = socket.spoof_send_first(packet, SUBNET_ADDR)?;

        Ok(Self {
            socket,
            self_addr: SUBNET_ADDR,
            peer_addr,
        })
    }
}

#[derive(Clone, Copy)]
struct RawTcpSock {
    dst: sockaddr_in,
    sock_r: i32,
    eph_port: Option<u16>,
    spoofed_eph_port: u16,
}
impl RawTcpSock {
    pub fn init(host_ip: Ipv4Addr) -> Self {
        let spoofed_eph_port = rand::rng().random_range(45000..54000);

        unsafe {
            let sock_r = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

            let dst = sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0, // ICMP uses no port
                sin_addr: in_addr {
                    s_addr: u32::from_ne_bytes(host_ip.octets()), // Network byte order
                },
                sin_zero: [0; 8],
            };

            let enable: libc::c_int = 1;
            let setopt = libc::setsockopt(
                sock_r,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            );

            Self {
                dst,
                sock_r,
                eph_port: None,
                spoofed_eph_port,
            }
        }
    }

    pub fn spoof_send_first(&mut self, packet: &mut [u8], src_ip: Ipv4Addr) -> Result<Ipv4Addr> {
        let (spoofed_packet, peer_addr, eph_port) =
            spoof_tcp_out(packet, src_ip, self.spoofed_eph_port).unwrap();

        if let None = self.eph_port {
            self.eph_port = Some(eph_port)
        }
        self.send(spoofed_packet)?;
        Ok(peer_addr)
    }
    pub fn spoof_send_cont(&self, packet: &mut [u8], src_ip: Ipv4Addr) -> Result<()> {
        let (spoofed_packet, _peer_addr, _eph_port) =
            spoof_tcp_out(packet, src_ip, self.spoofed_eph_port).unwrap();

        self.send(spoofed_packet)
    }
    fn send(&self, spoofed_packet: Vec<u8>) -> Result<()> {
        unsafe {
            let res = sendto(
                self.sock_r,
                spoofed_packet.as_ptr() as *const c_void,
                spoofed_packet.len(),
                0,
                &self.dst as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_in>() as u32,
            );
            if res < 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    unsafe fn wait_for_recv(&self) -> Result<()> {
        let mut fds = [pollfd {
            fd: self.sock_r,
            events: POLLIN,
            revents: 0,
        }];

        while fds[0].revents & POLLIN == 0 {
            let result = poll(fds.as_mut_ptr(), 1, 500);
            if result < 0 {
                return Err(io::Error::last_os_error().into());
            }
        }

        info!("Polling successful");
        Ok(())
    }

    pub fn spoof_recv(&self, peer_ip: Ipv4Addr) -> Result<Vec<u8>> {
        let mut rec_buf = [0u8; MTU_SIZE];
        unsafe {
            //self.wait_for_recv()?;
            let data_size = recvfrom(
                self.sock_r,
                rec_buf.as_mut_ptr() as *mut c_void,
                rec_buf.len(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            );

            if data_size < 0 {
                return Err(io::Error::last_os_error().into());
            } else {
                println!("received packet");
            }
            Ok(spoof_tcp_in(
                &mut rec_buf[..data_size as usize],
                peer_ip,
                self.eph_port.unwrap(),
            )
            .unwrap())
        }
    }
}

//
// fn run_server() -> Result<()> {
//     let server_socket = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8345);
//     let listener = TcpListener::bind(SocketAddr::V4(server_socket))?;
//     let mut addr_pool = dhc::AddrPool::create();
//     addr_pool.claim(SERVER_ADDR)?;
//
//     let mut session_registry = SessionRegistry::create();
//     session_registry.try_claim(0)?;
//
//     let tls_config = get_tls_config()?;
//
//     for stream in listener.incoming() {
//         let raw_tcp_stream = stream?;
//         let client_socket = if let SocketAddr::V4(sock_addr) = raw_tcp_stream.peer_addr()? {
//             sock_addr
//         } else {
//             return Err(Error::new(
//                 ErrorKind::UnsupportedProtocol,
//                 format!("Server only supports Ipv4"),
//             ));
//         };
//         info!("Client connected from socket {client_socket}");
//
//         let mut secure_stream = StreamOwned::new(
//             ServerConnection::new(Arc::new(tls_config.clone())).unwrap(),
//             raw_tcp_stream,
//         );
//
//         if let Some((offered_addr, session_id)) = handshake::try_assign_address(
//             &mut addr_pool,
//             &mut session_registry,
//             &mut secure_stream,
//             client_socket,
//         ) {
//             addr_pool.claim(offered_addr)?;
//
//             // Pass stream to forward traffic
//             handle_client(&mut secure_stream, session_id, SERVER_ADDR, offered_addr)?;
//
//             addr_pool.release(offered_addr)?;
//         }
//
//         // If an address could not be assigned, the client is dropped
//     }
//
//     Ok(())
// }
//
// fn handle_client(
//     stream: &mut SecureStream,
//     session_id: SessionID,
//     server_addr: Ipv4Addr,
//     client_addr: Ipv4Addr,
// ) -> Result<()> {
//     let mut read_buf = [0; MTU_SIZE];
//     //let interface = setup(server_addr, client_addr)?;
//
//     let server_port = 53555;
//     loop {
//         let size = stream.read(&mut read_buf)?;
//         if size == 0 {
//             info!("Client with session {session_id:#x} disconnected!");
//             return Ok(());
//         }
//
//         info!("Received {size} bytes");
//         info!("{:?}", &read_buf[..size]);
//         // forward packet
//
//         let res = if read_buf[9] == 6 {
//             info!("Found TCP");
//             info!("eph port is {server_port:?}");
//             connect_tcp(
//                 Ipv4Addr::new(192, 168, 1, 69),
//                 &mut read_buf[..size],
//                 client_addr,
//                 server_port,
//             )
//             .unwrap()
//         } else if read_buf[9] == 1 {
//             info!("Found ICMP");
//             Some(create_echo_reply(&read_buf[..size]).unwrap())
//         } else {
//             info!("Found invalid next IP protocol");
//             None
//         };
//
//         if let Some(mut response) = res {
//             info!("Writing back!");
//             stream.write_all(&mut response)?;
//         } else {
//             info!("Nothing to write back!");
//         }
//     }
// }
//
// fn connect_tcp(
//     host_ip: Ipv4Addr,
//     packet: &mut [u8],
//     peer_ip: Ipv4Addr,
//     server_eph_port: u16,
// ) -> Result<Option<Vec<u8>>> {
//     unsafe {
//         if let Some((spoofed_packet, dst_ip, eph_port)) =
//             spoof_tcp(packet, host_ip, server_eph_port)
//         {
//             println!("Spoofed is {spoofed_packet:?}");

//             if setopt < 0 {
//                 return Err(io::Error::last_os_error().into());
//             } else {
//                 println!("set opts {setopt}");
//             }
//
//             println!("sending packet: {:?}", spoofed_packet);

//
//             if res < 0 {
//                 return Err(io::Error::last_os_error().into());
//             } else {
//                 println!("sent {} bytes", res);
//             }
//
//             let mut rec_buf = [0u8; 1500];

//             } else {
//                 Ok(None)
//             }
//         } else {
//             Err(Error::new(ErrorKind::Other, format!("No TCP packet...")))
//         }
//     }
// }
//
fn spoof_tcp_out(
    buf: &mut [u8],
    src_ip: Ipv4Addr,
    spoofed_eph_port: u16,
) -> Option<(Vec<u8>, Ipv4Addr, u16)> {
    let mut packet = MutableIpv4Packet::new(buf)?;
    let peer_addr = packet.get_source();

    let mut tcp_part = packet.payload().to_owned().clone();
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_part)?;
    let eph_port = tcp_packet.get_source();
    tcp_packet.set_source(spoofed_eph_port);
    let tcp_checksum = tcp::ipv4_checksum(
        &TcpPacket::new(tcp_packet.packet())?,
        &src_ip,
        &packet.get_destination(),
    );
    tcp_packet.set_checksum(tcp_checksum);

    packet.set_source(src_ip);
    packet.set_payload(tcp_packet.packet());
    let ip_checksum = ipv4::checksum(&Ipv4Packet::new(packet.packet())?);
    packet.set_checksum(ip_checksum);

    Some((packet.packet().to_owned(), peer_addr, eph_port))
}

fn spoof_tcp_in(buf: &mut [u8], peer_ip: Ipv4Addr, eph_port: u16) -> Option<Vec<u8>> {
    let mut packet = MutableIpv4Packet::new(buf)?;

    let mut tcp_part = packet.payload().to_owned().clone();
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_part)?;
    tcp_packet.set_destination(eph_port);
    let tcp_checksum = tcp::ipv4_checksum(
        &TcpPacket::new(tcp_packet.packet())?,
        &packet.get_source(),
        &peer_ip,
    );
    tcp_packet.set_checksum(tcp_checksum);

    packet.set_destination(peer_ip);
    packet.set_payload(tcp_packet.packet());
    let ip_checksum = ipv4::checksum(&Ipv4Packet::new(packet.packet())?);
    packet.set_checksum(ip_checksum);

    Some(packet.packet().to_owned())
}
