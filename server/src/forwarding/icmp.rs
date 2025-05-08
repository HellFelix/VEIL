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

use super::{AbstractSock, Connection, RawSock};
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
        unimplemented!()
    }
    fn spoof_ip_next_out(
        &mut self,
        packet: &mut [u8],
        src_addr: std::net::Ipv4Addr,
        dst_addr: std::net::Ipv4Addr,
    ) -> Option<()> {
        unimplemented!()
    }
}

#[derive(Clone, Copy)]
pub struct IcmpConnection {
    sock: RawIcmpSock,
}
impl Connection for IcmpConnection {
    type SockType = RawIcmpSock;
    async fn send_to_remote_host(&mut self, packet: &mut [u8]) -> vpn_core::Result<()> {
        unimplemented!()
    }
    async fn recv_from_remote_host(&self) -> vpn_core::Result<Vec<u8>> {
        unimplemented!()
    }
    async fn init_from(packet: &mut [u8], mut stream: crate::SecureStream) -> vpn_core::Result<()> {
        let ip_packet = Ipv4Packet::new(&packet).unwrap();
        let icmp_packet = IcmpPacket::new(ip_packet.payload()).unwrap();

        if ip_packet.get_destination() == SERVER_ADDR && icmp_packet.get_icmp_type() == EchoRequest
        {
            // TODO: This should be moved to a separate tokio task
            let mut read_buf = [0u8; MTU_SIZE];
            let mut size = packet.len();

            read_buf[..size].copy_from_slice(&packet);
            loop {
                info!("Found packet {:?}", &read_buf[..size]);
                stream
                    .write(&echo::create_echo_reply(&read_buf[..size]).unwrap())
                    .await?;
                size = stream.read(&mut read_buf).await?;
            }
        } else {
            // Run forwarding
        }

        Ok(())
    }
    async fn run_forwarding(self, stream: crate::SecureStream) -> vpn_core::Result<()> {
        unimplemented!()
    }
}
