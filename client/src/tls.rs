use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use log::*;

use rustls::{pki_types::ServerName, version::TLS13, ClientConfig, ClientConnection, StreamOwned};

use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpStream, UnixStream},
    sync::{
        broadcast,
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    task::JoinHandle,
};
use tokio_rustls::{client::TlsStream, Connect, TlsAcceptor, TlsConnector};
use vpn_core::{
    network::{
        dhc::{DeAuthStage, Handshake, SessionID},
        SERVER_ADDR,
    },
    system::{setup, TunInterface, MTU_SIZE},
    tls::*,
    Error, ErrorKind, Result,
};

use crate::{commands::Command, ServerConf};

pub type SecureStream = TlsStream<TcpStream>;
pub type SecureRead = ReadHalf<SecureStream>;
pub type SecureWrite = WriteHalf<SecureStream>;

fn get_tls_config() -> Result<ClientConfig> {
    let client_cert = load_certs("/etc/veil/certs/client.crt")?;
    let client_key = load_private_key("/etc/veil/certs/client.key")?;
    let roots = load_root_cert_store("/etc/veil/certs/rootCA.pem")?;

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
    pub async fn run(self, controller: broadcast::Receiver<Command>) {
        let (sender, receiver) = channel(100);
        let (tls_reader, tls_writer) = split(self.stream);
        let interface = self.interface.clone();

        let write_handle = tokio::spawn(async move {
            Self::handle_write(tls_writer, receiver).await.unwrap();
        });
        let sender_clone = sender.clone();
        let tun_handle = tokio::spawn(async move {
            Self::handle_tun_read(sender, self.interface).await.unwrap();
        });

        let unix_handle = tokio::spawn(async move {
            Self::handle_unix_read(sender_clone, controller, self.session_id)
                .await
                .unwrap();
        });
        let remote_handle = tokio::spawn(async move {
            Self::handle_remote_read(
                tls_reader,
                interface,
                self.session_id,
                (write_handle, tun_handle, unix_handle),
            )
            .await
            .unwrap();
            info!("Finished reader");
        });

        if let Ok(_) = remote_handle.await {
            info!("Shutdown complete");
        } else {
            error!("Shutdown failed");
        }
    }

    async fn handle_remote_read(
        mut reader: SecureRead,
        interface: TunInterface,
        session_id: SessionID,
        handles: (JoinHandle<()>, JoinHandle<()>, JoinHandle<()>),
    ) -> Result<()> {
        let mut res_buf = [0; MTU_SIZE];
        'listener: loop {
            if let Ok(len) = reader.read(&mut res_buf[4..]).await {
                if let Some(deauth) = DeAuthStage::from_bytes(&res_buf[4..len + 4]) {
                    match deauth {
                        DeAuthStage::Acknowledge(id) => {
                            if id == session_id {
                                info!("Disconnect acknowledged. Shutting down");
                                break 'listener;
                            }
                        }
                        _ => {}
                    }
                } else {
                    info!("Found length {len}");
                    res_buf[3] = 2;
                    info!("Got {:?}", &res_buf[..len + 4]);
                    interface.write(&mut res_buf[..4 + len])?;
                }
            } else {
                continue;
            }
        }
        handles.0.abort();
        handles.1.abort();
        handles.2.abort();
        Ok(())
    }

    async fn handle_tun_read(sender: Sender<Vec<u8>>, interface: TunInterface) -> Result<()> {
        let mut req_buf = [0; MTU_SIZE];
        loop {
            // TODO: Implement AsyncRead for interface so that read can be performed without
            // calling yield_now.
            let mut size = 0;
            while size == 0 {
                if let Some(s) = interface.read(&mut req_buf)? {
                    size = s as usize;
                }

                if size > 0 {
                    info!("Forwarding, {:?}", &req_buf[4..size]);
                    sender.send(req_buf[4..size].to_owned()).await.unwrap();
                }
                tokio::task::yield_now().await;
            }
        }
    }

    async fn handle_unix_read(
        sender: Sender<Vec<u8>>,
        mut controller: broadcast::Receiver<Command>,
        session_id: SessionID,
    ) -> Result<()> {
        println!("Listening for commands");
        while let Ok(cmd) = controller.recv().await {
            info!("Got command");
            match cmd {
                Command::Disconnect(forceful) => {
                    info!("Got disconnect request");
                    if forceful {
                        panic!("Forced shutdown");
                    } else {
                        sender
                            .send(DeAuthStage::Disconnect(session_id).to_bytes().unwrap())
                            .await
                            .unwrap();
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn handle_write(mut writer: SecureWrite, mut receiver: Receiver<Vec<u8>>) -> Result<()> {
        info!("Writer running");
        while let Some(msg) = receiver.recv().await {
            writer.write_all(&msg).await?;
            info!("Forwarding {:?}", &msg);
        }
        Ok(())
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
