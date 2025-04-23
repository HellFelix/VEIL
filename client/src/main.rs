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
use tls::SecureStream;

#[derive(Debug, Clone, Copy)]
#[toml_cfg::toml_config()]
pub struct ServerConfig {
    #[default(0)]
    pub address: u32,
    #[default(0)]
    pub port: u16,
}

fn main() {
    match init() {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }
}

fn init() -> Result<()> {
    init_logger("client", "info", false);
    let mut client = Client::try_setup(3, SERVER_CONFIG)?;
    if let Err(e) = client.run_traffic() {
        // Catch and log without interruping shut down process
        error!("{e}");
    }
    info!("Shutting down gracefully");
    Ok(())
}

struct Client {
    stream: SecureStream,
    session_id: SessionID,
    interface: TunInterface,
    shutdown_flag: Receiver<()>,
}
impl Client {
    pub fn run_traffic(&mut self) -> Result<()> {
        let mut req_buf = [0; MTU_SIZE];
        while let Err(TryRecvError::Empty) = self.shutdown_flag.try_recv() {
            if let Some(size) = self.interface.read(&mut req_buf)? {
                let packet = Ipv4Packet::new(&req_buf[..size as usize]).unwrap();
                if packet.get_source() == self.interface.local_addr {
                    info!("Found echo!");
                    self.stream.write_all(&req_buf[..size as usize])?;

                    let mut res_buf = [0; MTU_SIZE];
                    let len = self.stream.read(&mut res_buf)?;
                    info!("Received {len} bytes");
                    self.interface.write(&mut res_buf[..len])?;
                } else {
                    info!("Found non-echo");
                }
            }
        }
        Ok(())
    }
}
