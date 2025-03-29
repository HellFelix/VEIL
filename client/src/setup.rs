use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use log::*;

use rustls::{
    pki_types::ServerName, version::TLS13, ClientConfig, ClientConnection, ConnectionCommon,
    SideData, StreamOwned,
};

pub struct SecureStream(StreamOwned<ClientConnection, TcpStream>);
impl SecureStream {
    pub fn new(conn: ClientConnection, sock: TcpStream) -> Self {
        Self(StreamOwned::new(conn, sock))
    }
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
    pub fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        info!("Closing TLS connection");
        self.0.conn.send_close_notify();

        self.0.flush()?;

        self.0.sock.shutdown(std::net::Shutdown::Both)?;

        Ok(())
    }
}
impl Drop for SecureStream {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            error!("Encountered error during shutdown: {e}");
        }
    }
}
