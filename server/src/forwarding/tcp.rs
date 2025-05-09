use std::net::Ipv4Addr;

use log::*;

use libc::IPPROTO_TCP;

use pnet::packet::{
    ipv4::Ipv4Packet,
    tcp::{self, MutableTcpPacket, TcpPacket},
    Packet,
};
use tokio::io::split;

use super::{AbstractConn, Connection, RawSock, SockOpts, StatefulSock};
use vpn_core::Result;

#[derive(Clone, Copy)]
pub struct RawTcpSock {
    abs: StatefulSock,
}
impl From<StatefulSock> for RawTcpSock {
    fn from(value: StatefulSock) -> Self {
        Self { abs: value }
    }
}
impl RawSock<StatefulSock> for RawTcpSock {
    const IPPROTO: i32 = IPPROTO_TCP;

    fn get_abstract(&self) -> StatefulSock {
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum TcpState {
    Run,
    Fin,
}

#[derive(Clone, Copy)]
pub struct TcpConnection {
    abs: AbstractConn<StatefulSock, RawTcpSock>,
    state: TcpState,
}

impl From<AbstractConn<StatefulSock, RawTcpSock>> for TcpConnection {
    fn from(value: AbstractConn<StatefulSock, RawTcpSock>) -> Self {
        TcpConnection {
            abs: value,
            state: TcpState::Run,
        }
    }
}

impl Connection<StatefulSock, RawTcpSock, TcpPacket<'_>> for TcpConnection {
    fn send_to_remote_host(&mut self, packet: &mut [u8]) -> Result<()> {
        self.abs.sock.spoof_send(packet, self.abs.self_addr)
    }
    fn recv_from_remote_host(&self) -> Result<Vec<u8>> {
        self.abs
            .sock
            .spoof_recv(self.abs.peer_addr, self.abs.dst_addr)
    }

    fn get_conn_opts(packet: &Ipv4Packet) -> Option<SockOpts> {
        let next_layer_packet = TcpPacket::new(packet.payload())?;

        Some(SockOpts {
            eph_port: Some(next_layer_packet.get_source()),
        })
    }
}
