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

use super::{AbstractConn, AbstractSock, Connection, RawSock};

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
        &self,
        packet: &mut [u8],
        src_addr: std::net::Ipv4Addr,
        dst_addr: std::net::Ipv4Addr,
    ) -> Option<()> {
        let mut udp_packet = MutableUdpPacket::new(packet)?;
        let eph_port = udp_packet.get_source();

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
    abs: AbstractConn<RawUdpSock>,
}

impl From<AbstractConn<RawUdpSock>> for UdpConnection {
    fn from(value: AbstractConn<RawUdpSock>) -> Self {
        UdpConnection { abs: value }
    }
}
impl Connection<RawUdpSock, UdpPacket<'_>> for UdpConnection {
    fn send_to_remote_host(&mut self, packet: &mut [u8]) -> Result<()> {
        self.abs.sock.spoof_send(packet, self.abs.self_addr)
    }
    fn recv_from_remote_host(&self) -> Result<Vec<u8>> {
        self.abs
            .sock
            .spoof_recv(self.abs.peer_addr, self.abs.dst_addr)
    }

    fn get_eph_port(packet: &Ipv4Packet) -> Option<u16> {
        let tcp_packet = UdpPacket::new(packet.payload())?;

        Some(tcp_packet.get_source())
    }
}
