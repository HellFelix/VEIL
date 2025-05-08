use std::{io::Write, os::unix::net::UnixStream};

use bincode::config;
use client::commands::*;

fn main() {
    let mut stream = UnixStream::connect("/tmp/veil.sock").unwrap();

    // let mut buf = Vec::new();
    // bincode::encode_into_slice(
    //     Command::Connect(String::from("main")),
    //     &mut buf,
    //     bincode::config::standard(),
    // )
    // .unwrap();

    let config = config::standard();
    let command = Command::Connect(String::from("main"));
    let encoded: Vec<u8> = bincode::encode_to_vec(&command, config).unwrap();
    println!("{encoded:?}");

    stream.write_all(&encoded).unwrap();
}
