use log::*;

use client;

use toml_cfg;

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
    match client::init(SERVER_CONFIG.address, SERVER_CONFIG.port).await {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }
}

pub enum Commands {
    Connect,
    Disconnect,

    Route,
}

enum RoutingRule {
    Create,
    Remove,
}
