use tokio_rustls::TlsAcceptor;

use encryption::get_tls_config;
use handshake::SessionRegistry;
use log::*;
use std::{
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
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

mod echo;
mod encryption;
mod forwarding;
use forwarding::{Connection, IcmpConnection, TcpConnection, UdpConnection};
mod handshake;

use echo::create_echo_reply;

use tokio_rustls::server::TlsStream;
type SecureStream = TlsStream<TcpStream>;

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

    match read_buf[9] {
        1 => IcmpConnection::init_from(&mut read_buf[..size], stream).await?,
        6 => TcpConnection::init_from(&mut read_buf[..size], stream).await?,
        17 => UdpConnection::init_from(&mut read_buf[..size], stream).await?,
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Unknown next protocol"),
            ))
        }
    }

    Ok(())
}
