use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    sync::{mpsc::channel, Arc},
    thread::sleep,
    time::Duration,
};

use log::*;

use rustls::{pki_types::ServerName, version::TLS13, ClientConfig, ClientConnection, StreamOwned};

use vpn_core::{
    network::{
        dhc::{Handshake, SessionID},
        SERVER_ADDR,
    },
    tls::*,
    utun, Error, ErrorKind, Result, TunInterface,
};

use crate::{Client, ServerConfig};

pub struct SecureStream(StreamOwned<ClientConnection, TcpStream>);
impl SecureStream {
    pub fn new(conn: ClientConnection, sock: TcpStream) -> Self {
        Self(StreamOwned::new(conn, sock))
    }
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.0.read(buf)?)
    }
    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        Ok(self.0.write_all(buf)?)
    }

    fn shutdown(&mut self) -> Result<()> {
        info!("Closing TLS connection");
        self.0.conn.send_close_notify();

        self.0.flush()?;

        self.0.sock.shutdown(std::net::Shutdown::Both)?;

        Ok(())
    }
}
impl Drop for SecureStream {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            error!("Encountered error during shutdown: {e}");
        }
    }
}

fn get_tls_config() -> Result<ClientConfig> {
    let client_cert = load_certs("../certs/client.crt")?;
    let client_key = load_private_key("../certs/client.key")?;
    let roots = load_root_cert_store("../certs/rootCA.pem")?;

    Ok(ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(client_cert, client_key)
        .unwrap())
}

const BUF_SIZE: usize = 100;
struct ClientSetup {
    stream: SecureStream,
    session_id: Option<SessionID>,
    interface: Option<TunInterface>,
    read_buffer: [u8; BUF_SIZE],
}
impl ClientSetup {
    pub fn finilize(self) -> Result<Client> {
        let (trigger, flag) = channel();

        if let Err(e) = ctrlc::set_handler(move || {
            info!("Got Keyboard interrupt. Shutting down");
            trigger.send(());

            sleep(Duration::from_millis(500));
            info!("Graceful shutdown failed within permitted time.");
            panic!("Force shutdown from keyboard interrupt");
        }) {
            warn!("Failed to set up graceful shutdown: {e}")
        }

        if let (Some(session_id), Some(interface)) = (self.session_id, self.interface) {
            Ok(Client {
                stream: self.stream,
                session_id,
                interface,
                shutdown_flag: flag,
            })
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!("Client is not setup properly."),
            ))
        }
    }

    pub fn connect_to_server(server_config: ServerConfig) -> Result<Self> {
        let server_socket = SocketAddrV4::new(
            Ipv4Addr::from_bits(server_config.address),
            server_config.port,
        );
        info!("Connecting to {server_socket}");
        let raw_tcp_stream = TcpStream::connect(server_socket)?;

        let mut res = Self {
            stream: SecureStream::new(
                ClientConnection::new(
                    Arc::new(get_tls_config()?),
                    ServerName::try_from("VEIL").unwrap(),
                )
                .unwrap(),
                raw_tcp_stream,
            ),
            session_id: None,
            interface: None,
            read_buffer: [0; BUF_SIZE],
        };

        res.run_handshake_protocol()?;

        Ok(res)
    }

    fn run_handshake_protocol(&mut self) -> Result<()> {
        let discovery = Handshake::initial_handshake();
        let session_id = discovery.get_session_id();
        self.stream.write_all(&mut discovery.to_bytes())?;
        info!("Sent discovery to server with session ID: {session_id:#x}");
        let expected_offer = discovery.advance()?;

        // Search for Offer
        let offer = self.try_read_handshake()?;
        offer.validate(Some(expected_offer))?;
        let offered_address = offer.get_addr()?;
        info!("Received offer {offered_address} from server. Sending request");

        // Send request
        let request = offer.advance()?;
        self.stream.write_all(&mut request.to_bytes())?;

        // Search for Acknowledgement
        let expected_ack = request.advance()?;
        let acknowledgement = self.try_read_handshake()?;
        acknowledgement.validate(Some(expected_ack))?;
        info!("Received acknowledgement. Initializing interface");

        // Set session ID and initialize utun intereface
        self.session_id = Some(session_id);
        self.interface = Some(utun::setup(offered_address, SERVER_ADDR)?);

        Ok(())
    }

    fn try_read_handshake(&mut self) -> Result<Handshake> {
        let recv_size = self.stream.read(&mut self.read_buffer)?;
        let res = Handshake::from_bytes(&self.read_buffer[..recv_size]);
        if res.is_rejection() {
            Err(Error::new(
                ErrorKind::Rejection,
                format!("Handshake was rejected by server"),
            ))
        } else {
            Ok(res)
        }
    }
}

impl Client {
    pub fn try_setup(mut retries: u8, server_config: ServerConfig) -> Result<Self> {
        loop {
            if retries == 0 {
                break Err(Error::new(
                    ErrorKind::MaxRetry,
                    format!("Exceeded maximum retries while trying to connect"),
                ));
            }
            match ClientSetup::connect_to_server(server_config) {
                Ok(res) => break Ok(res.finilize()?),
                Err(e) => {
                    warn!("Client setup failed: {e}");
                    retries -= 1;
                    continue;
                }
            }
        }
    }
}
