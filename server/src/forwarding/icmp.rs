use libc::IPPROTO_ICMP;

use log::*;

use super::{AbstractConn, Connection, RawSock, SockOpts, StatelessSock};
use crate::echo;
use pnet::packet::{
    icmp::{IcmpPacket, IcmpTypes::EchoRequest},
    ipv4::Ipv4Packet,
    Packet,
};

#[derive(Clone, Copy)]
pub struct RawIcmpSock {
    abs: StatelessSock,
}
impl From<StatelessSock> for RawIcmpSock {
    fn from(value: StatelessSock) -> Self {
        Self { abs: value }
    }
}
impl RawSock<StatelessSock> for RawIcmpSock {
    const IPPROTO: i32 = IPPROTO_ICMP;

    fn get_abstract(&self) -> StatelessSock {
        self.abs
    }

    fn spoof_ip_next_in(
        &self,
        packet: &mut [u8],
        src_addr: std::net::Ipv4Addr,
        dst_addr: std::net::Ipv4Addr,
    ) -> Option<()> {
        Some(())
    }
    fn spoof_ip_next_out(
        &self,
        packet: &mut [u8],
        src_addr: std::net::Ipv4Addr,
        dst_addr: std::net::Ipv4Addr,
    ) -> Option<()> {
        Some(())
    }
}

#[derive(Clone, Copy)]
pub struct IcmpConnection {
    abs: AbstractConn<StatelessSock, RawIcmpSock>,
}
impl From<AbstractConn<StatelessSock, RawIcmpSock>> for IcmpConnection {
    fn from(value: AbstractConn<StatelessSock, RawIcmpSock>) -> Self {
        Self { abs: value }
    }
}
impl Connection<StatelessSock, RawIcmpSock, IcmpPacket<'_>> for IcmpConnection {
    fn send_to_remote_host(&mut self, packet: &mut [u8]) -> vpn_core::Result<()> {
        self.abs.sock.spoof_send(packet, self.abs.self_addr)
    }
    fn recv_from_remote_host(&self) -> vpn_core::Result<Vec<u8>> {
        self.abs
            .sock
            .spoof_recv(self.abs.peer_addr, self.abs.dst_addr)
    }

    fn get_conn_opts(packet: &Ipv4Packet) -> Option<SockOpts> {
        Some(SockOpts { eph_port: None })
    }
}
