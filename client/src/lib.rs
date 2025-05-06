use log::*;
use pnet::packet::ipv4::Ipv4Packet;

use std::{
    io,
    sync::mpsc::{Receiver, TryRecvError},
};

use vpn_core::{
    logs::init_logger, network::dhc::SessionID, system::TunInterface, system::MTU_SIZE, Result,
};

mod tls;
use tls::{Client, SecureStream};

#[derive(Clone, Copy)]
struct ServerConfig {
    pub address: u32,
    pub port: u16,
}

pub async fn init(address: u32, port: u16) -> Result<()> {
    init_logger("client", "info", false);
    let client = Client::try_setup(3, ServerConfig { address, port }).await?;
    client.run().await;
    info!("Up and running!");
    Ok(())
}
