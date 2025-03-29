use log::*;

use std::{
    io,
    sync::mpsc::{Receiver, TryRecvError},
};

use vpn_core::{network::dhc::SessionID, utils::logs::init_logger, TunInterface, MTU_SIZE};

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

fn init() -> io::Result<()> {
    init_logger("client", "info", false);
    let mut client = Client::try_setup(3, SERVER_CONFIG)?;
    client.run_traffic()?;
    Ok(())
}

struct Client {
    stream: SecureStream,
    session_id: SessionID,
    interface: TunInterface,
    shutdown_flag: Receiver<()>,
}
impl Client {
    pub fn run_traffic(&mut self) -> io::Result<()> {
        let mut req_buf = [0; MTU_SIZE];
        while let Err(TryRecvError::Empty) = self.shutdown_flag.try_recv() {
            if let Some(size) = self.interface.read(&mut req_buf) {
                self.stream.write_all(&req_buf[..size as usize])?;

                let mut res_buf = [0; MTU_SIZE];
                let len = self.stream.read(&mut res_buf)?;
                info!("Received {len} bytes");
                self.interface.write(&mut res_buf[..len])?;
            }
        }
        info!("Shutting down gracefully");
        Ok(())
    }
}
