use log::*;
use std::{
    io::{self, Error, ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
};
use vpn_core::{
    network::dhc::{self, Message, Stage},
    utils::{logs::init_logger, shared::SERVER_ADDR, utun},
    MTU_SIZE,
};

mod icmp;
use icmp::create_echo_reply;

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

    for stream in listener.incoming() {
        let mut s = stream?;
        let client_socket = if let SocketAddr::V4(sock_addr) = s.peer_addr()? {
            sock_addr
        } else {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Server only supports Ipv4"),
            ));
        };
        info!("Client connected from socket {client_socket}");

        let mut read_buf = [0; 100];

        // Check for discovery
        let disc_size = s.read(&mut read_buf)?;
        let discovery = Message::from_bytes(&read_buf[..disc_size]);
        discovery.validate(Stage::Discover)?;
        info!("Received discovery from client {client_socket}");

        // Offer IP
        let offered_addr = addr_pool.find_unclaimed()?;
        info!("Offering address {offered_addr} to {client_socket}");
        s.write_all(&mut dhc::Message::new(Stage::Offer(Some(offered_addr))).to_bytes())?;

        // Check for request
        let req_size = s.read(&mut read_buf)?;
        let request = dhc::Message::from_bytes(&read_buf[..req_size]);
        request.validate(Stage::Request(offered_addr))?;
        info!("Client {client_socket} has requested address {offered_addr}. Sending Acknowledgement...");

        // Send Acknowledgement
        s.write_all(&mut dhc::Message::new(Stage::Acknowledge(offered_addr)).to_bytes())?;

        addr_pool.claim(offered_addr)?;

        // Pass stream to forward traffic
        handle_client(s, client_socket, SERVER_ADDR, offered_addr)?;

        addr_pool.release(offered_addr)?;
    }

    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    client_socket: SocketAddrV4,
    server_addr: Ipv4Addr,
    client_addr: Ipv4Addr,
) -> io::Result<()> {
    let mut read_buf = [0; MTU_SIZE];
    let interface = utun::setup(server_addr, client_addr)?;

    loop {
        let size = stream.read(&mut read_buf)?;
        if size == 0 {
            info!("Client from {client_socket} disconnected!");
            return Ok(());
        }

        // forward packet

        let mut res = create_echo_reply(&read_buf[..size]).unwrap();
        stream.write_all(&mut res)?;
    }
}
