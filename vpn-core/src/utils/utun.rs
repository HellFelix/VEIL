use log::*;
use std::{io, net::Ipv4Addr, process};

use crate::{open_utun, TunInterface};

pub fn setup(interface_ip: Ipv4Addr, peer_ip: Ipv4Addr) -> io::Result<TunInterface> {
    let interface = unsafe { open_utun()? };
    info!("Successfully initialized {} interface", interface.name);

    process::Command::new("ifconfig")
        .args([
            interface.name.clone(),
            format!("{interface_ip}"),
            format!("{peer_ip}"),
            String::from("up"),
        ])
        .status()
        .unwrap();
    info!("Successfully initialized Tunnel endpoint");
    info!("Interface IP is set to {interface_ip}");
    info!("Peer IP is set to {peer_ip}");

    Ok(interface)
}
