use libc::IPPROTO_ICMP;

use log::*;

use pnet::packet::{
    icmp::{IcmpPacket, IcmpTypes::EchoRequest},
    ipv4::Ipv4Packet,
    Packet,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use vpn_core::{network::SERVER_ADDR, system::MTU_SIZE};

use super::{AbstractConn, AbstractSock, Connection, RawSock};
use crate::echo;

#[derive(Clone, Copy)]
pub struct RawIcmpSock {
    abs: AbstractSock,
}
impl From<AbstractSock> for RawIcmpSock {
    fn from(value: AbstractSock) -> Self {
        Self { abs: value }
    }
}
impl RawSock for RawIcmpSock {
    const IPPROTO: i32 = IPPROTO_ICMP;

    fn get_abstract(&self) -> AbstractSock {
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
    abs: AbstractConn<RawIcmpSock>,
}
impl From<AbstractConn<RawIcmpSock>> for IcmpConnection {
    fn from(value: AbstractConn<RawIcmpSock>) -> Self {
        Self { abs: value }
    }
}
impl Connection<RawIcmpSock, IcmpPacket<'_>> for IcmpConnection {
    fn send_to_remote_host(&mut self, packet: &mut [u8]) -> vpn_core::Result<()> {
        self.abs.sock.spoof_send(packet, self.abs.self_addr)
    }
    fn recv_from_remote_host(&self) -> vpn_core::Result<Vec<u8>> {
        self.abs
            .sock
            .spoof_recv(self.abs.peer_addr, self.abs.dst_addr)
    }

    fn get_eph_port(packet: &Ipv4Packet) -> Option<u16> {
        None
    }
}
