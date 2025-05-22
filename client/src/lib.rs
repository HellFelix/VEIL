use commands::Command;
use log::*;
use pnet::packet::ipv4::Ipv4Packet;
use tokio::{net::UnixStream, sync::broadcast::Receiver};

use std::{io, net::IpAddr};

use vpn_core::{logs::init_logger, Result};

pub mod commands;

mod tls;
use tls::{Client, SecureStream};

#[derive(Debug, Clone, Copy)]
pub struct ServerConf {
    pub address: IpAddr,
    pub port: u16,
}

pub async fn init(conf: &ServerConf, controller: Receiver<Command>) -> Result<()> {
    //init_logger("client", "info", false);
    let client = Client::try_setup(3, &conf).await?;
    client.run(controller).await;
    info!("Up and running!");
    Ok(())
}
