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

use std::{ffi::c_void, ptr, thread::sleep, time::Duration};

use encryption::get_tls_config;
use handshake::SessionRegistry;
use log::*;
use rustls::{ServerConnection, StreamOwned};
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    sync::Arc,
};
use vpn_core::{
    logs::init_logger,
    network::{
        dhc::{self, SessionID},
        SERVER_ADDR,
    },
    system::MTU_SIZE,
    Error, ErrorKind, Result,
};

mod echo;
mod encryption;
mod handshake;

use echo::create_echo_reply;
type SecureStream = StreamOwned<ServerConnection, TcpStream>;

fn main() {
    match init() {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }
}

fn init() -> Result<()> {
    init_logger("server", "info", true);
    run_server()?;
    Ok(())
}

fn run_server() -> Result<()> {
    let server_socket = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8345);
    let listener = TcpListener::bind(SocketAddr::V4(server_socket))?;
    let mut addr_pool = dhc::AddrPool::create();
    addr_pool.claim(SERVER_ADDR)?;

    let mut session_registry = SessionRegistry::create();
    session_registry.try_claim(0)?;

    let tls_config = get_tls_config()?;

    for stream in listener.incoming() {
        let raw_tcp_stream = stream?;
        let client_socket = if let SocketAddr::V4(sock_addr) = raw_tcp_stream.peer_addr()? {
            sock_addr
        } else {
            return Err(Error::new(
                ErrorKind::UnsupportedProtocol,
                format!("Server only supports Ipv4"),
            ));
        };
        info!("Client connected from socket {client_socket}");

        let mut secure_stream = StreamOwned::new(
            ServerConnection::new(Arc::new(tls_config.clone())).unwrap(),
            raw_tcp_stream,
        );

        if let Some((offered_addr, session_id)) = handshake::try_assign_address(
            &mut addr_pool,
            &mut session_registry,
            &mut secure_stream,
            client_socket,
        ) {
            addr_pool.claim(offered_addr)?;

            // Pass stream to forward traffic
            handle_client(&mut secure_stream, session_id, SERVER_ADDR, offered_addr)?;

            addr_pool.release(offered_addr)?;
        }

        // If an address could not be assigned, the client is dropped
    }

    Ok(())
}

fn handle_client(
    stream: &mut SecureStream,
    session_id: SessionID,
    server_addr: Ipv4Addr,
    client_addr: Ipv4Addr,
) -> Result<()> {
    let mut read_buf = [0; MTU_SIZE];
    //let interface = setup(server_addr, client_addr)?;

    let server_port = 53555;
    loop {
        let size = stream.read(&mut read_buf)?;
        if size == 0 {
            info!("Client with session {session_id:#x} disconnected!");
            return Ok(());
        }

        info!("Received {size} bytes");
        info!("{:?}", &read_buf[..size]);
        // forward packet

        let res = if read_buf[9] == 6 {
            info!("Found TCP");
            info!("eph port is {server_port:?}");
            connect_tcp(
                Ipv4Addr::new(192, 168, 1, 69),
                &mut read_buf[..size],
                client_addr,
                server_port,
            )
            .unwrap()
        } else if read_buf[9] == 1 {
            info!("Found ICMP");
            Some(create_echo_reply(&read_buf[..size]).unwrap())
        } else {
            info!("Found invalid next IP protocol");
            None
        };

        if let Some(mut response) = res {
            info!("Writing back!");
            stream.write_all(&mut response)?;
        } else {
            info!("Nothing to write back!");
        }
    }
}

fn connect_tcp(
    host_ip: Ipv4Addr,
    packet: &mut [u8],
    peer_ip: Ipv4Addr,
    server_eph_port: u16,
) -> Result<Option<Vec<u8>>> {
    unsafe {
        if let Some((spoofed_packet, dst_ip, eph_port)) =
            spoof_tcp(packet, host_ip, server_eph_port)
        {
            println!("Spoofed is {spoofed_packet:?}");
            let sock_r = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

            let dst = sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0, // ICMP uses no port
                sin_addr: in_addr {
                    s_addr: u32::from_ne_bytes(dst_ip.octets()), // Network byte order
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

            if setopt < 0 {
                return Err(io::Error::last_os_error().into());
            } else {
                println!("set opts {setopt}");
            }

            println!("sending packet: {:?}", spoofed_packet);
            let res = sendto(
                sock_r,
                spoofed_packet.as_ptr() as *const c_void,
                spoofed_packet.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_in>() as u32,
            );

            if res < 0 {
                return Err(io::Error::last_os_error().into());
            } else {
                println!("sent {} bytes", res);
            }

            let mut rec_buf = [0u8; 1500];

            let mut fds = [pollfd {
                fd: sock_r,
                events: POLLIN,
                revents: 0,
            }];

            info!("polling");
            let result = poll(fds.as_mut_ptr(), 1, 500);

            if result < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            if fds[0].revents & POLLIN != 0 {
                let data_size = recvfrom(
                    sock_r,
                    rec_buf.as_mut_ptr() as *mut c_void,
                    rec_buf.len(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );

                if data_size < 0 {
                    return Err(io::Error::last_os_error().into());
                } else {
                    println!("received {:?}", &rec_buf[..data_size as usize]);
                }
                Ok(Some(
                    spoof_tcp_back(&mut rec_buf[..data_size as usize], peer_ip, eph_port).unwrap(),
                ))
            } else {
                Ok(None)
            }
        } else {
            Err(Error::new(ErrorKind::Other, format!("No TCP packet...")))
        }
    }
}

fn spoof_tcp(
    buf: &mut [u8],
    src_ip: Ipv4Addr,
    server_eph_port: u16,
) -> Option<(Vec<u8>, Ipv4Addr, u16)> {
    let mut packet = MutableIpv4Packet::new(buf)?;

    let mut tcp_part = packet.payload().to_owned().clone();
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_part)?;
    let eph_port = tcp_packet.get_source();
    tcp_packet.set_source(server_eph_port);
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

    Some((
        packet.packet().to_owned(),
        packet.get_destination(),
        eph_port,
    ))
}

fn spoof_tcp_back(buf: &mut [u8], peer_ip: Ipv4Addr, eph_port: u16) -> Option<Vec<u8>> {
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
