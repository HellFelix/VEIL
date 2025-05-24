use std::env::args;
use std::ffi::CString;
use std::{io, process};
use std::{io::Read, net::IpAddr, os::unix::net::UnixListener};

use libc::chown;
use log::*;

use client::commands::*;
use client::{self, ServerConf};

mod conf;
use conf::{ClientConf, add_server, extract_conf};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{Receiver, channel};
use vpn_core::Result;

#[tokio::main]
async fn main() {
    let mut exec_args = args().skip(1);
    vpn_core::logs::init_logger("daemon", "info", false);
    let listener = UnixListener::bind("/tmp/veil.sock").unwrap();

    change_sock_ownership(
        "/tmp/veil.sock",
        exec_args.next().unwrap().parse().unwrap(),
        exec_args.next().unwrap().parse().unwrap(),
    )
    .unwrap();

    let mut conf = extract_conf().unwrap();

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
                        Command::Config(rule) => match rule {
                            ConfigRule::Server(opt) => match opt {
                                ServerOpt::Add(name, addr, port) => {
                                    if let Err(e) = add_server(&name, addr, port) {
                                        error!("Failed to add server config {e}");
                                    }
                                }
                                ServerOpt::Remove(name) => {}
                            },
                            ConfigRule::Route(opt, route_rule) => {}
                            ConfigRule::Reload => {
                                conf = extract_conf().unwrap();
                            }
                        },
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

fn change_sock_ownership(path: &str, uid: u32, gid: u32) -> io::Result<()> {
    let c_path = CString::new(path)?;
    let result = unsafe { chown(c_path.as_ptr(), uid, gid) };

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
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
