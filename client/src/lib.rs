use log::*;
use pnet::packet::ipv4::Ipv4Packet;

use std::{
    io,
    net::IpAddr,
    sync::mpsc::{Receiver, TryRecvError},
};

use vpn_core::{logs::init_logger, Result};

pub mod commands;

mod tls;
use tls::{Client, SecureStream};

#[derive(Debug)]
pub struct ServerConf {
    pub address: IpAddr,
    pub port: u16,
}

pub async fn init(conf: &ServerConf) -> Result<()> {
    //init_logger("client", "info", false);
    let client = Client::try_setup(3, &conf).await?;
    client.run().await;
    info!("Up and running!");
    Ok(())
}
