use log::*;

use std::{
    io::{self, Error, ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
};

use vpn_core::{
    network::{
        dhc::{self, Handshake, Stage},
        SERVER_ADDR,
    },
    utils::{logs::init_logger, utun},
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

#[derive(Debug)]
#[toml_cfg::toml_config()]
pub struct ServerConfig {
    #[default(0)]
    pub address: u32,
    #[default(0)]
    pub port: u16,
}

fn connect_to_server() -> io::Result<(TcpStream, TunInterface)> {
    let server_socket = SocketAddrV4::new(
        Ipv4Addr::from_bits(SERVER_CONFIG.address),
        SERVER_CONFIG.port,
    );
    info!("connecting to {server_socket}");
    let mut stream = TcpStream::connect(server_socket)?;

    let discovery = Handshake::initial_handshake();
    let session_id = discovery.get_session_id();
    stream.write_all(&mut discovery.to_bytes())?;
    info!("Sent discovery to server with session ID: {session_id:#x}");
    let expected_offer = discovery.advance()?;

    let mut read_buf = [0; 100];

    // Search for Offer
    let offer_size = stream.read(&mut read_buf)?;
    let offer = Handshake::from_bytes(&read_buf[..offer_size]);
    offer.validate(Some(expected_offer))?;
    let offered_address = offer.get_addr()?;
    info!("Received offer {offered_address} from server. Sending request");

    // Send request
    let request = offer.advance()?;
    stream.write_all(&mut request.to_bytes())?;

    // Search for Acknowledgement
    let expected_ack = request.advance()?;
    let ack_size = stream.read(&mut read_buf)?;
    let acknowledgement = Handshake::from_bytes(&read_buf[..ack_size]);
    acknowledgement.validate(Some(expected_ack))?;
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
