use log::*;

use std::{io, process};

use vpn_core::{
    open_utun,
    utils::{logs::init_logger, utun},
    TunInterface,
};

fn main() {
    match init() {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }
}

fn init() -> io::Result<()> {
    init_logger("client", "info", false);
    let interface = utun::setup("10.0.0.1", "10.0.0.2")?;

    Ok(())
}
