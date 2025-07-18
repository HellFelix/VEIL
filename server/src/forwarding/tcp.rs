use std::{marker::PhantomData, net::Ipv4Addr};

use log::*;

use libc::IPPROTO_TCP;

use pnet::packet::{
    ipv4::Ipv4Packet,
    tcp::{self, MutableTcpPacket, TcpPacket},
    Packet,
};

use super::{AbstractConn, ConnState, Connection, LifeCycle, RawSock, SockOpts, StatefulSock};
use vpn_core::Result;

#[derive(Clone, Copy)]
enum TcpState {
    // Handshake
    Syn,
    SynAck,
    Running,

    // Graceful shutdown
    Fin,
    FinAck,
    Finished,

    // Forced shutdown
    Rst,
}
const ACK_MASK: u8 = 0b0001_0000;
const RST_MASK: u8 = 0b0000_0100;
const SYN_MASK: u8 = 0b0000_0010;
const FIN_MASK: u8 = 0b0000_0001;

fn flag_set(flags: u8, field_mask: u8) -> bool {
    flags & field_mask != 0
}

#[derive(Clone, Copy)]
pub struct TcpLifeCycle {
    conn_state: ConnState,
    tcp_state: TcpState,
}
impl LifeCycle for TcpLifeCycle {
    type P<'a> = TcpPacket<'a>;
    fn initialize() -> Self {
        Self {
            conn_state: ConnState::Alive,
            tcp_state: TcpState::Syn,
        }
    }
    fn get_state(&self) -> ConnState {
        match self.tcp_state {
            TcpState::Finished => ConnState::Finished,
            TcpState::Rst => ConnState::Broken,
            _ => ConnState::Alive,
        }
    }
    fn check_state(&mut self, input: TcpPacket<'_>) {
        let flags = input.get_flags();
        if flag_set(flags, RST_MASK) {
            self.tcp_state = TcpState::Rst;
            warn!("Found TCP Reset!");
        } else {
            match self.tcp_state {
                TcpState::Syn => {
                    if flag_set(flags, SYN_MASK) && flag_set(flags, ACK_MASK) {
                        self.tcp_state = TcpState::SynAck;
                    }
                }
                TcpState::SynAck => {
                    if flag_set(flags, ACK_MASK) {
                        self.tcp_state = TcpState::SynAck;
                    }
                }
                TcpState::Running => {
                    if flag_set(flags, FIN_MASK) {
                        self.tcp_state = TcpState::Fin;
                    }
                }
                TcpState::Fin => {
                    if flag_set(flags, FIN_MASK) && flag_set(flags, ACK_MASK) {
                        self.tcp_state = TcpState::FinAck;
                    }
                }
                TcpState::FinAck => {
                    if flag_set(flags, ACK_MASK) {
                        self.tcp_state = TcpState::Finished;
                    }
                }
                TcpState::Finished => {
                    warn!("Finished TCP connection still running");
                }
                TcpState::Rst => {
                    warn!("Reset TCP connection still running");
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct RawTcpSock {
    abs: StatefulSock,
}
impl From<StatefulSock> for RawTcpSock {
    fn from(value: StatefulSock) -> Self {
        Self { abs: value }
    }
}
impl RawSock<StatefulSock, TcpLifeCycle> for RawTcpSock {
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

#[derive(Clone, Copy)]
pub struct TcpConnection {
    abs: AbstractConn<StatefulSock, RawTcpSock, TcpLifeCycle>,
}

impl From<AbstractConn<StatefulSock, RawTcpSock, TcpLifeCycle>> for TcpConnection {
    fn from(value: AbstractConn<StatefulSock, RawTcpSock, TcpLifeCycle>) -> Self {
        TcpConnection { abs: value }
    }
}

impl Connection<StatefulSock, RawTcpSock, TcpPacket<'_>, TcpLifeCycle> for TcpConnection {
    fn send_to_remote_host(&mut self, packet: &mut [u8]) -> Result<()> {
        self.abs.sock.spoof_send(packet, self.abs.self_addr)
    }
    fn recv_from_remote_host(&self) -> Result<Vec<u8>> {
        self.abs
            .sock
            .spoof_recv(self.abs.peer_addr, self.abs.dst_addr)
    }

    fn get_conn_opts<'a>(packet: &'a Ipv4Packet) -> Option<SockOpts<TcpLifeCycle>> {
        let next_layer_packet = TcpPacket::new(packet.payload())?;

        Some(SockOpts {
            eph_port: Some(next_layer_packet.get_source()),
            life_cycle: TcpLifeCycle::initialize(),
        })
    }
}
