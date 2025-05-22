use std::env::args;
use std::{io, process};
use std::{io::Read, net::IpAddr, os::unix::net::UnixListener};

use log::*;

use client::commands::*;
use client::{self, ServerConf};

mod conf;
use conf::{ClientConf, extract_conf};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{Receiver, channel};
use vpn_core::Result;

#[tokio::main]
async fn main() {
    let mut exec_args = args().skip(1);
    vpn_core::logs::init_logger("daemon", "info", false);
    let listener = UnixListener::bind("/tmp/veil.sock").unwrap();

    #[cfg(target_os = "linux")]
    grant_rw_acl("/tmp/veil.sock", &exec_args.next().unwrap()).unwrap();

    let conf = extract_conf().unwrap();

    // accept connections and process them, spawning a new thread for each one
    loop {
        let (sender, _) = channel::<Command>(100);
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buf = [0; 50];

                    let size = stream.read(&mut buf).unwrap();
                    info!("{:?}", &buf[..size]);

                    let cmd = Command::from_bytes(&buf[..size]);

                    match cmd {
                        Command::Connect(server) => match server {
                            ServerAddr::Default => {
                                connect(
                                    *conf.servers.get(&String::from("main")).unwrap(),
                                    sender.subscribe(),
                                )
                                .await
                            }
                            ServerAddr::Configured(name) => {
                                connect(
                                    *conf.servers.get(&name.to_owned()).unwrap(),
                                    sender.subscribe(),
                                )
                                .await
                            }
                            ServerAddr::Override(address, port) => {
                                connect(ServerConf { address, port }, sender.subscribe()).await
                            }
                        },
                        Command::Disconnect(_forceful) => {
                            sender.send(Command::Disconnect(_forceful)).unwrap();
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    /* connection failed */
                    break;
                }
            }
        }
    }
}

fn grant_rw_acl(path: &str, user: &str) -> io::Result<()> {
    let status = process::Command::new("setfacl")
        .args(["-m", &format!("u:{}:rw", user), path])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "setfacl command failed",
        ))
    }
}
async fn connect(conf: ServerConf, controller: Receiver<Command>) {
    tokio::spawn(async move {
        match client::init(&conf, controller).await {
            Ok(_) => info!("System shut down without error"),
            Err(e) => error!("System exited with {e:?}"),
        }
    });
}
