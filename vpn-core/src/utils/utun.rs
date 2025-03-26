use log::*;
use std::{io, process};

use crate::{open_utun, TunInterface};

pub fn setup(interface_ip: &str, peer_ip: &str) -> io::Result<TunInterface> {
    let interface = unsafe { open_utun()? };
    info!("Successfully initialized {} interface", interface.name);

    process::Command::new("ifconfig")
        .args([
            interface.name.clone(),
            String::from(interface_ip),
            String::from(peer_ip),
            String::from("up"),
        ])
        .status()
        .unwrap();
    info!("Successfully initialized Tunnel endpoint");
    info!("Interface IP is set to {interface_ip}");
    info!("Peer IP is set to {peer_ip}");

    Ok(interface)
}
