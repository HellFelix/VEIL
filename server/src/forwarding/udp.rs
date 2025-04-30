use std::net::Ipv4Addr;

use libc::IPPROTO_UDP;
use log::*;
use pnet::packet::{
    ipv4::Ipv4Packet,
    udp::{self, MutableUdpPacket, UdpPacket},
    Packet,
};
use tokio::io::split;

use vpn_core::Result;

use crate::{SecureStream, SERVER_CONFIG};

use super::{AbstractSock, Connection, RawSock};

#[derive(Clone, Copy)]
pub struct RawUdpSock {
    abs: AbstractSock,
}
impl From<AbstractSock> for RawUdpSock {
    fn from(value: AbstractSock) -> Self {
        Self { abs: value }
    }
}
impl RawSock for RawUdpSock {
    const IPPROTO: i32 = IPPROTO_UDP;

    fn get_abstract(&self) -> AbstractSock {
        self.abs
    }

    fn spoof_ip_next_out(
        &mut self,
        packet: &mut [u8],
        src_addr: std::net::Ipv4Addr,
        dst_addr: std::net::Ipv4Addr,
    ) -> Option<()> {
        let mut udp_packet = MutableUdpPacket::new(packet)?;
        let eph_port = udp_packet.get_source();

        self.abs.set_eph_if_not(eph_port);

        udp_packet.set_source(self.get_abstract().spoofed_eph_port);
        let udp_checksum =
            udp::ipv4_checksum(&UdpPacket::new(udp_packet.packet())?, &src_addr, &dst_addr);
        udp_packet.set_checksum(udp_checksum);
        Some(())
    }

    fn spoof_ip_next_in(
        &self,
        packet: &mut [u8],
        src_addr: std::net::Ipv4Addr,
        dst_addr: std::net::Ipv4Addr,
    ) -> Option<()> {
        let mut udp_packet = MutableUdpPacket::new(packet)?;
        udp_packet.set_destination(self.abs.eph_port.unwrap());
        let udp_checksum =
            udp::ipv4_checksum(&UdpPacket::new(udp_packet.packet())?, &src_addr, &dst_addr);
        udp_packet.set_checksum(udp_checksum);
        Some(())
    }
}

#[derive(Clone, Copy)]
pub struct UdpConnection {
    sock: RawUdpSock,
    self_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
}
impl Connection for UdpConnection {
    type SockType = RawUdpSock;

    async fn send_to_remote_host(&mut self, packet: &mut [u8]) -> Result<()> {
        self.sock.spoof_send(packet, self.self_addr)
    }
    async fn recv_from_remote_host(&self) -> Result<Vec<u8>> {
        self.sock.spoof_recv(self.peer_addr)
    }

    async fn init_from(packet: &mut [u8], stream: SecureStream) -> Result<()> {
        let ip_packet = Ipv4Packet::new(packet).unwrap();

        let sock = RawUdpSock::init(ip_packet.get_destination());

        let mut conn = Self {
            sock,
            self_addr: SERVER_CONFIG.get_ipv4_addr(),
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
