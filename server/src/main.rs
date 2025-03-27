use log::*;
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
};
use vpn_core::{
    utils::{logs::init_logger, utun},
    TunInterface, MTU_SIZE,
};

mod icmp;
use icmp::create_echo_reply;
fn main() {
    match init() {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }
}

fn init() -> io::Result<()> {
    init_logger("server", "info", true);
    let interface = utun::setup("10.0.0.2", "10.0.0.3")?;
    run_server(&interface)?;
    Ok(())
}

fn run_server(interface: &TunInterface) -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8345")?;

    for stream in listener.incoming() {
        info!("Client connected!");
        handle_stream(stream?, interface)?;
    }

    Ok(())
}

fn handle_stream(mut stream: TcpStream, interface: &TunInterface) -> io::Result<()> {
    let mut read_buf = [0; MTU_SIZE];

    loop {
        let size = stream.read(&mut read_buf)?;
        if size == 0 {
            info!("Client disconnected!");
            return Ok(());
        }

        // forward packet

        let mut res = create_echo_reply(&read_buf[..size]).unwrap();
        stream.write_all(&mut res)?;
    }
}
