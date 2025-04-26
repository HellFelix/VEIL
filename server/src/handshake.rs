use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
};

use log::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vpn_core::network::dhc::{AddrPool, Handshake, SessionID};
use vpn_core::{Error, ErrorKind, Result};

use crate::SecureStream;

const BUF_SIZE: usize = 100;

pub async fn try_assign_address(
    addr_pool: &mut AddrPool,
    session_registry: &mut SessionRegistry,
    stream: &mut SecureStream,
    client_socket: SocketAddrV4,
) -> Option<(Ipv4Addr, SessionID)> {
    let mut read_buf = [1; BUF_SIZE];
    let (discovery, session_id) =
        match accept_discovery(stream, client_socket, session_registry, &mut read_buf).await {
            Ok(res) => res,
            Err(e) => {
                warn!("Rejecting discovery from {client_socket} due to protocol violation: {e}");
                stream
                    .write_all(&mut Handshake::discovery_rejection(*client_socket.ip()).to_bytes());
                return None;
            }
        };
    match offeer_addr_protocol(discovery, session_id, addr_pool, stream).await {
        Ok(addr) => Some((addr, session_id)),
        Err(e) => {
            warn!("Handshake with client on session {session_id:#x} failed due to protocol violation: {e}");
            stream.write_all(
                &mut Handshake::in_session_rejection(*client_socket.ip(), session_id).to_bytes(),
            );
            None
        }
    }
}

async fn accept_discovery(
    stream: &mut SecureStream,
    client_socket: SocketAddrV4,
    session_registry: &mut SessionRegistry,
    read_buf: &mut [u8; BUF_SIZE],
) -> Result<(Handshake, SessionID)> {
    // Check for discovery
    let disc_size = stream.read(read_buf).await?;
    let discovery = Handshake::from_bytes(&read_buf[..disc_size]);
    discovery.validate(None)?;
    let session_id = discovery.get_session_id();
    info!("Received discovery from client {client_socket}. Session ID is {session_id:#x}");
    session_registry.try_claim(session_id)?;

    Ok((discovery, session_id))
}

async fn offeer_addr_protocol(
    discovery: Handshake,
    session_id: SessionID,
    addr_pool: &mut AddrPool,
    stream: &mut SecureStream,
) -> Result<Ipv4Addr> {
    let mut read_buf = [0; 100];
    // Offer IP
    let offered_addr = addr_pool.find_unclaimed()?;
    let mut offer = discovery.advance()?;
    offer.set_offer(offered_addr);
    info!("Offering address {offered_addr} to client on session {session_id:#x}");
    stream.write_all(&mut offer.to_bytes()).await?;

    // Check for request
    let expected_request = offer.advance()?;
    let req_size = stream.read(&mut read_buf).await?;
    let request = Handshake::from_bytes(&read_buf[..req_size]);
    request.validate(Some(expected_request))?;
    info!("Client on session {session_id:#x} has sent approved request for address {offered_addr}. Sending Acknowledgement...");

    // Send Acknowledgement
    stream.write_all(&request.advance()?.to_bytes()).await?;

    Ok(offered_addr)
}

pub struct SessionRegistry(Vec<SessionID>);
impl SessionRegistry {
    pub fn create() -> Self {
        Self(vec![])
    }
    pub fn try_claim(&mut self, entry: SessionID) -> Result<()> {
        if self.0.contains(&entry) {
            Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("Client attempted to claim preexisting session ID {entry:#x}"),
            ))
        } else {
            self.0.push(entry);
            Ok(())
        }
    }
}
