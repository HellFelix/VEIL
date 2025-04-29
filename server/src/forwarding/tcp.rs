use std::net::Ipv4Addr;

use log::*;

use libc::IPPROTO_TCP;

use pnet::packet::{
    ipv4::Ipv4Packet,
    tcp::{self, MutableTcpPacket, TcpPacket},
    Packet,
};
use tokio::io::split;

use super::{AbstractSock, Connection, RawSock};
use crate::{SecureStream, SUBNET_ADDR};
use vpn_core::Result;

#[derive(Clone, Copy)]
pub struct RawTcpSock {
    abs: AbstractSock,
}
impl From<AbstractSock> for RawTcpSock {
    fn from(value: AbstractSock) -> Self {
        Self { abs: value }
    }
}
impl RawSock for RawTcpSock {
    const IPPROTO: i32 = IPPROTO_TCP;

    fn get_abstract(&self) -> AbstractSock {
        self.abs
    }

    fn spoof_ip_next_out(
        &mut self,
        packet: &mut [u8],
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
    ) -> Option<()> {
        let mut tcp_packet = MutableTcpPacket::new(packet)?;
        let eph_port = tcp_packet.get_source();

        self.abs.set_eph_if_not(eph_port);

        tcp_packet.set_source(self.get_abstract().spoofed_eph_port);
        let tcp_checksum =
            tcp::ipv4_checksum(&TcpPacket::new(tcp_packet.packet())?, &src_addr, &dst_addr);
        tcp_packet.set_checksum(tcp_checksum);
        Some(())
    }

    fn spoof_ip_next_in(
        &self,
        packet: &mut [u8],
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
    ) -> Option<()> {
        let mut tcp_packet = MutableTcpPacket::new(packet)?;
        tcp_packet.set_destination(self.abs.eph_port.unwrap());
        let tcp_checksum =
            tcp::ipv4_checksum(&TcpPacket::new(tcp_packet.packet())?, &src_addr, &dst_addr);
        tcp_packet.set_checksum(tcp_checksum);
        Some(())
    }
}
#[derive(Clone, Copy)]
pub struct TcpConnection {
    sock: RawTcpSock,
    self_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
}

impl Connection for TcpConnection {
    type SockType = RawTcpSock;

    async fn send_to_remote_host(&mut self, packet: &mut [u8]) -> Result<()> {
        self.sock.spoof_send(packet, self.self_addr)
    }
    async fn recv_from_remote_host(&self) -> Result<Vec<u8>> {
        self.sock.spoof_recv(self.peer_addr)
    }

    async fn init_from(packet: &mut [u8], stream: SecureStream) -> Result<()> {
        let ip_packet = Ipv4Packet::new(packet).unwrap();

        let sock = RawTcpSock::init(ip_packet.get_destination());

        let mut conn = Self {
            sock,
            self_addr: SUBNET_ADDR,
            peer_addr: ip_packet.get_source(),
        };

        conn.send_to_remote_host(packet).await?;

        conn.run_forwarding(stream).await
    }

    async fn run_forwarding(mut self, stream: SecureStream) -> Result<()> {
        let (tls_reader, tls_writer) = split(stream);

        let recv_handle = tokio::spawn(async move {
            info!("starting receiver");
            self.handle_recv(tls_writer).await.unwrap();
        });

        let forward_handle = tokio::spawn(async move {
            info!("starting writer");
            self.handle_forward(tls_reader).await.unwrap();
        });

        let (_recv_res, _forward_res) = tokio::join!(recv_handle, forward_handle);

        Ok(())
    }
}
