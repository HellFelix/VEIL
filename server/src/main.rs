use log::*;
use std::io;

use vpn_core::{open_utun, utils::logs::init_logger};
fn main() {
    match init() {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }
}

fn init() -> io::Result<()> {
    init_logger("server", "info", true);
    Ok(())
}
