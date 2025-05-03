use std::net::Ipv4Addr;

use log::*;

use libc::IPPROTO_TCP;

use pnet::packet::{
    ipv4::Ipv4Packet,
    tcp::{self, MutableTcpPacket, TcpPacket},
    Packet,
};
use tokio::io::split;

use super::{AbstractConn, AbstractSock, Connection, RawSock};
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
        &self,
        packet: &mut [u8],
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
    ) -> Option<()> {
        let mut tcp_packet = MutableTcpPacket::new(packet)?;

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

impl From<AbstractConn<RawTcpSock>> for TcpConnection {
    fn from(value: AbstractConn<RawTcpSock>) -> Self {
        TcpConnection {
            sock: value.sock,
            self_addr: value.self_addr,
            peer_addr: value.peer_addr,
        }
    }
}

impl Connection<RawTcpSock> for TcpConnection {
    fn send_to_remote_host(&mut self, packet: &mut [u8]) -> Result<()> {
        self.sock.spoof_send(packet, self.self_addr)
    }
    fn recv_from_remote_host(&self) -> Result<Vec<u8>> {
        self.sock.spoof_recv(self.peer_addr)
    }

    // async fn init_from(packet: &mut [u8], stream: SecureStream) -> Result<()> {
    //     let ip_packet = Ipv4Packet::new(packet).unwrap();
    //
    //     let sock = RawTcpSock::init(ip_packet.get_destination());
    //
    //     let mut conn = Self {
    //         sock,
    //         self_addr: SERVER_CONFIG.get_ipv4_addr(),
    //         peer_addr: ip_packet.get_source(),
    //     };
    //
    //     conn.send_to_remote_host(packet).await?;
    //
    //     conn.run_forwarding(stream).await
    // }

    fn get_eph_port(packet: &Ipv4Packet) -> Option<u16> {
        let tcp_packet = TcpPacket::new(packet.payload())?;

        Some(tcp_packet.get_source())
    }
}
