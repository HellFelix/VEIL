use log::*;

use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use vpn_core::{
    utils::{logs::init_logger, utun},
    TunInterface, MTU_SIZE,
};

fn main() {
    match init() {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }
}

fn init() -> io::Result<()> {
    init_logger("client", "info", false);
    let interface = utun::setup("10.0.0.2", "10.0.0.1")?;
    run_traffic(interface)?;

    Ok(())
}

fn run_traffic(interface: TunInterface) -> io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:8345")?;

    let mut req_buf = [0; MTU_SIZE];
    loop {
        if let Some(size) = interface.read(&mut req_buf) {
            info!("Read {:?}", &req_buf[..size as usize]);

            stream.write_all(&req_buf[..size as usize])?;

            let mut res_buf = [0; MTU_SIZE];
            let len = stream.read(&mut res_buf)?;
            info!("Received {:?}", &res_buf[..len]);
            interface.write(&mut res_buf[..len])?;
        }
    }
}
