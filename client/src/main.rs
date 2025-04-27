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

#[derive(Debug, Clone, Copy)]
#[toml_cfg::toml_config()]
pub struct ServerConfig {
    #[default(0)]
    pub address: u32,
    #[default(0)]
    pub port: u16,
}

#[tokio::main]
async fn main() {
    match init().await {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }
}

async fn init() -> Result<()> {
    init_logger("client", "info", false);
    let client = Client::try_setup(3, SERVER_CONFIG).await?;
    client.run().await;
    info!("Up and running!");
    Ok(())
}
