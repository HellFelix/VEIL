use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};

pub fn run_server() {
    let listener = TcpListener::bind("0.0.0.0:8345").unwrap();

    for stream in listener.incoming() {
        if let Ok(s) = stream {
            thread::spawn(|| handle_stream(s));
        }
    }
}

fn handle_stream(mut stream: TcpStream) {
    let mut buf = [0u8; 1500];
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 {
            break;
        } // connection closed
        println!("Got {} bytes", n);
        stream.write_all(&buf[..n]).unwrap(); // echo back
    }
}

pub fn send_stream(msg: &[u8]) {
    let mut stream = TcpStream::connect("127.0.0.1:8345").unwrap();
    println!("Connected to server");

    stream.write_all(msg).unwrap();
}
