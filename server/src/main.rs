use encryption::get_tls_config;
use handshake::SessionRegistry;
use log::*;
use rustls::{ServerConnection, StreamOwned};
use std::{
    io::{self, Error, ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    sync::Arc,
};
use vpn_core::{
    network::{
        dhc::{self, SessionID},
        SERVER_ADDR,
    },
    utils::{logs::init_logger, utun},
    MTU_SIZE,
};

mod encryption;
mod handshake;
mod icmp;
use icmp::create_echo_reply;

type SecureStream = StreamOwned<ServerConnection, TcpStream>;

fn main() {
    match init() {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }
}

fn init() -> io::Result<()> {
    init_logger("server", "info", true);
    run_server()?;
    Ok(())
}

fn run_server() -> io::Result<()> {
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
                ErrorKind::Unsupported,
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
) -> io::Result<()> {
    let mut read_buf = [0; MTU_SIZE];
    let interface = utun::setup(server_addr, client_addr)?;

    loop {
        let size = stream.read(&mut read_buf)?;
        if size == 0 {
            info!("Client with session {session_id:#x} disconnected!");
            return Ok(());
        }

        // forward packet

        let mut res = create_echo_reply(&read_buf[..size]).unwrap();
        stream.write_all(&mut res)?;
    }
}
