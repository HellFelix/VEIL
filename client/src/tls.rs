use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    sync::{
        mpsc::{channel, Receiver, TryRecvError},
        Arc,
    },
    thread::sleep,
    time::Duration,
};

use log::*;

use rustls::{pki_types::ServerName, version::TLS13, ClientConfig, ClientConnection, StreamOwned};

use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, Connect, TlsAcceptor, TlsConnector};
use vpn_core::{
    network::{
        dhc::{Handshake, SessionID},
        SERVER_ADDR,
    },
    system::{setup, TunInterface, MTU_SIZE},
    tls::*,
    Error, ErrorKind, Result,
};

use crate::ServerConf;

pub type SecureStream = TlsStream<TcpStream>;
pub type SecureRead = ReadHalf<SecureStream>;
pub type SecureWrite = WriteHalf<SecureStream>;
// impl SecureStream {
//     pub fn new(conn: ClientConnection, sock: TcpStream) -> Self {
//         Self(StreamOwned::new(conn, sock))
//     }
//     pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
//         Ok(self.0.read(buf)?)
//     }
//     pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
//         Ok(self.0.write_all(buf)?)
//     }
//
//     fn shutdown(&mut self) -> Result<()> {
//         info!("Closing TLS connection");
//         self.0.conn.send_close_notify();
//
//         self.0.flush()?;
//
//         self.0.sock.shutdown(std::net::Shutdown::Both)?;
//
//         Ok(())
//     }
// }
// impl Drop for SecureStream {
//     fn drop(&mut self) {
//         if let Err(e) = self.shutdown() {
//             error!("Encountered error during shutdown: {e}");
//         }
//     }
// }

fn get_tls_config() -> Result<ClientConfig> {
    let client_cert = load_certs("/etc/systemd/veil/certs/client.crt")?;
    let client_key = load_private_key("/etc/systemd/veil/certs/client.key")?;
    let roots = load_root_cert_store("/etc/systemd/veil/certs/rootCA.pem")?;

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
        if let (Some(session_id), Some(interface)) = (self.session_id, self.interface) {
            Ok(Client {
                stream: self.stream,
                session_id,
                interface,
            })
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!("Client is not setup properly."),
            ))
        }
    }

    pub async fn connect_to_server(server_config: &ServerConf) -> Result<Self> {
        let connector = TlsConnector::from(Arc::new(get_tls_config()?));
        let server_socket = SocketAddr::new(server_config.address, server_config.port);
        info!("Connecting to {server_socket}");
        let stream = connector
            .connect(
                ServerName::try_from("VEIL").unwrap(),
                TcpStream::connect(server_socket).await?,
            )
            .await?;

        let mut res = Self {
            stream,
            session_id: None,
            interface: None,
            read_buffer: [0; BUF_SIZE],
        };

        res.run_handshake_protocol().await?;

        Ok(res)
    }

    async fn run_handshake_protocol(&mut self) -> Result<()> {
        let discovery = Handshake::initial_handshake();
        let session_id = discovery.get_session_id();
        self.stream.write_all(&mut discovery.to_bytes()).await?;
        info!("Sent discovery to server with session ID: {session_id:#x}");
        let expected_offer = discovery.advance()?;

        // Search for Offer
        let offer = self.try_read_handshake().await?;
        offer.validate(Some(expected_offer))?;
        let offered_address = offer.get_addr()?;
        info!("Received offer {offered_address} from server. Sending request");

        // Send request
        let request = offer.advance()?;
        self.stream.write_all(&mut request.to_bytes()).await?;

        // Search for Acknowledgement
        let expected_ack = request.advance()?;
        let acknowledgement = self.try_read_handshake().await?;
        acknowledgement.validate(Some(expected_ack))?;
        info!("Received acknowledgement. Initializing interface");

        // Set session ID and initialize utun intereface
        self.session_id = Some(session_id);
        self.interface = Some(setup(offered_address, SERVER_ADDR)?);

        Ok(())
    }

    async fn try_read_handshake(&mut self) -> Result<Handshake> {
        let recv_size = self.stream.read(&mut self.read_buffer).await?;
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

pub struct Client {
    stream: SecureStream,
    session_id: SessionID,
    interface: TunInterface,
}
impl Client {
    // pub fn run_traffic(&mut self) -> Result<()> {

    //     }
    //     Ok(())
    // }

    pub async fn run(self) {
        let (reader, writer) = split(self.stream);
        let interface_clone = self.interface.clone();

        let write_handle = tokio::spawn(async move {
            Self::handle_write(writer, self.interface).await.unwrap();
        });
        let read_handle = tokio::spawn(async move {
            Self::handle_read(reader, interface_clone).await.unwrap();
            info!("Finished reader");
        });

        let (_write_res, _read_res) = tokio::join!(write_handle, read_handle);
        _read_res.unwrap();
    }

    async fn handle_read(mut reader: SecureRead, interface: TunInterface) -> Result<()> {
        info!("Reader running");
        let mut res_buf = [0; MTU_SIZE];
        loop {
            info!("Reading");
            if let Ok(len) = reader.read(&mut res_buf[4..]).await {
                info!("Found length {len}");
                res_buf[3] = 2;
                info!("Got {:?}", &res_buf[..len + 4]);
                interface.write(&mut res_buf[..4 + len])?;
            } else {
                continue;
            }
        }
    }

    async fn handle_write(mut writer: SecureWrite, interface: TunInterface) -> Result<()> {
        info!("Writer running");
        let mut req_buf = [0; MTU_SIZE];
        loop {
            // TODO: Fix this weird "future is not `Send`" issue
            let mut size = 0;
            while size == 0 {
                if let Some(s) = interface.read(&mut req_buf)? {
                    size = s as usize;
                }
                if size > 0 {
                    writer.write_all(&req_buf[4..size]).await?;
                    info!("Forwarding {:?}", &req_buf[..size as usize]);
                }
            }
        }
    }

    pub async fn try_setup(mut retries: u8, server_config: &ServerConf) -> Result<Self> {
        loop {
            if retries == 0 {
                break Err(Error::new(
                    ErrorKind::MaxRetry,
                    format!("Exceeded maximum retries while trying to connect"),
                ));
            }
            match ClientSetup::connect_to_server(server_config).await {
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
