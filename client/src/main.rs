use log::*;

use std::{
    io::{self, Error, ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
};

use vpn_core::{
    utils::{
        dhc::{self, Message, Stage},
        logs::init_logger,
        shared::SERVER_ADDR,
        utun,
    },
    TunInterface, MTU_SIZE,
};

fn main() {
    match init() {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }
}

fn init() -> io::Result<()> {
    init_logger("client", "info", false);
    let (mut stream, interface) = connect_to_server()?;
    run_traffic(&mut stream, interface)?;
    Ok(())
}

fn connect_to_server() -> io::Result<(TcpStream, TunInterface)> {
    let server_socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8345);
    let mut stream = TcpStream::connect(server_socket)?;
    let client_socket = if let SocketAddr::V4(sock_addr) = stream.local_addr()? {
        sock_addr
    } else {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("Server only supports Ipv4"),
        ));
    };

    stream.write_all(
        &mut dhc::Message::new(dhc::Stage::Discover, client_socket, server_socket).to_bytes(),
    )?;
    info!("Sent discovery to server");

    let mut read_buf = [0; 100];

    // Search for Offer
    let offer_size = stream.read(&mut read_buf)?;
    let offer = Message::from_bytes(&read_buf[..offer_size]);
    offer.validate(server_socket, client_socket, Stage::Offer(None))?;
    let offered_address = offer.get_addr()?;
    info!("Received offer {offered_address}. Sending request");

    // Send request
    stream.write_all(
        &mut dhc::Message::new(
            Stage::Request(offered_address),
            client_socket,
            server_socket,
        )
        .to_bytes(),
    )?;

    // Search for Acknowledgement
    let ack_size = stream.read(&mut read_buf)?;
    let acknowledgement = Message::from_bytes(&read_buf[..ack_size]);
    acknowledgement.validate(
        server_socket,
        client_socket,
        Stage::Acknowledge(offered_address),
    )?;
    info!("Received acknowledgement. Initializing interface");

    // Initialize TUN interface
    let interface = utun::setup(offered_address, SERVER_ADDR)?;

    Ok((stream, interface))
}

fn run_traffic(stream: &mut TcpStream, interface: TunInterface) -> io::Result<()> {
    let mut req_buf = [0; MTU_SIZE];
    loop {
        if let Some(size) = interface.read(&mut req_buf) {
            stream.write_all(&req_buf[..size as usize])?;

            let mut res_buf = [0; MTU_SIZE];
            let len = stream.read(&mut res_buf)?;
            info!("Received {len} bytes");
            interface.write(&mut res_buf[..len])?;
        }
    }
}
