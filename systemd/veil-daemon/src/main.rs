use std::{io::Read, net::IpAddr, os::unix::net::UnixListener};

use bincode::{Decode, Encode};
use log::*;

use client::commands::*;
use client::{self, ServerConf};

mod conf;
use conf::{ClientConf, extract_conf};
use serde::{Deserialize, Serialize};
use vpn_core::Result;

#[tokio::main]
async fn main() {
    vpn_core::logs::init_logger("daemon", "info", false);
    let conf = extract_conf().unwrap();

    loop {
        let listener = UnixListener::bind("/tmp/veil.sock").unwrap();

        // accept connections and process them, spawning a new thread for each one
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buf = Vec::new();
                    stream.read_to_end(&mut buf).unwrap();

                    info!("{buf:?}");

                    let (command, _len): (Command, usize) =
                        bincode::decode_from_slice(&buf[..], bincode::config::standard()).unwrap();

                    match command {
                        Command::Connect(server) => {
                            connect(conf.servers.get(&server).unwrap()).await.unwrap()
                        }
                        _ => {}
                    }
                }
                Err(err) => {
                    /* connection failed */
                    break;
                }
            }
        }
    }
}

async fn connect(conf: &ServerConf) -> Result<()> {
    match client::init(&conf).await {
        Ok(_) => info!("System shut down without error"),
        Err(e) => error!("System exited with {e:?}"),
    }

    Ok(())
}
