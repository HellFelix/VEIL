use std::{ffi::c_void, io, net::Ipv4Addr, ptr};

use log::*;

use libc::{
    in_addr, recvfrom, send, sendto, sockaddr_in, socket, AF_INET, AF_PACKET, ETH_P_ALL,
    IPPROTO_ICMP, IPPROTO_TCP, POLLIN, SOCK_RAW,
};

use pnet::packet::{
    ipv4::{self, Ipv4Packet, MutableIpv4Packet},
    Packet,
};
use rand::Rng;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::{SecureStream, SUBNET_ADDR};
use vpn_core::{system::MTU_SIZE, Result};

mod tcp;
pub use tcp::TcpConnection;

mod icmp;
pub use icmp::IcmpConnection;

type SecureRead = ReadHalf<SecureStream>;
type SecureWrite = WriteHalf<SecureStream>;

#[derive(Clone, Copy)]
pub struct AbstractSock {
    dst: sockaddr_in,
    sock_r: i32,
    eph_port: Option<u16>,
    spoofed_eph_port: u16,
}
impl AbstractSock {
    pub fn set_eph_if_not(&mut self, eph_port: u16) {
        match self.eph_port {
            Some(_) => {}
            None => self.eph_port = Some(eph_port),
        }
    }

    pub fn send(&self, spoofed_packet: Vec<u8>) -> Result<()> {
        unsafe {
            let res = sendto(
                self.sock_r,
                spoofed_packet.as_ptr() as *const c_void,
                spoofed_packet.len(),
                0,
                &self.dst as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_in>() as u32,
            );
            if res < 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
}

pub trait RawSock: Clone + Copy + Sized + From<AbstractSock> {
    const IPPROTO: i32;

    fn get_abstract(&self) -> AbstractSock;

    //TODO: Do error handling from kernel results
    fn init(host_addr: Ipv4Addr) -> Self {
        //TODO: Set the range from the systems available ports
        let spoofed_eph_port = rand::rng().random_range(45000..54000);

        unsafe {
            let sock_r = socket(AF_INET, SOCK_RAW, Self::IPPROTO);

            let dst = sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: in_addr {
                    s_addr: u32::from_ne_bytes(host_addr.octets()),
                },
                sin_zero: [0; 8],
            };

            let enable: libc::c_int = 1;
            let setopt = libc::setsockopt(
                sock_r,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            );

            Self::from(AbstractSock {
                dst,
                sock_r,
                eph_port: None,
                spoofed_eph_port,
            })
        }
    }

    fn spoof_send(&mut self, packet: &mut [u8], src_ip: Ipv4Addr) -> Result<()> {
        let (spoofed_packet, _peer_addr) = self.spoof_out(packet, src_ip).unwrap();

        self.send(spoofed_packet)
    }

    fn spoof_out(&mut self, buf: &mut [u8], src_ip: Ipv4Addr) -> Option<(Vec<u8>, Ipv4Addr)> {
        let mut packet = MutableIpv4Packet::new(buf)?;
        let peer_addr = packet.get_source();

        let mut payload = packet.payload().to_owned().clone();
        self.spoof_ip_next_out(&mut payload, src_ip, packet.get_destination())?;

        packet.set_source(src_ip);
        packet.set_payload(&payload);
        let ip_checksum = ipv4::checksum(&Ipv4Packet::new(packet.packet())?);
        packet.set_checksum(ip_checksum);

        Some((packet.packet().to_owned(), peer_addr))
    }

    fn send(&self, packet: Vec<u8>) -> Result<()> {
        self.get_abstract().send(packet)
    }

    fn spoof_recv(&self, peer_ip: Ipv4Addr) -> Result<Vec<u8>> {
        let mut rec_buf = [0u8; MTU_SIZE];
        unsafe {
            let data_size = recvfrom(
                self.get_abstract().sock_r,
                rec_buf.as_mut_ptr() as *mut c_void,
                rec_buf.len(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            );

            if data_size < 0 {
                return Err(io::Error::last_os_error().into());
            } else {
                println!("received packet");
            }
            Ok(self
                .spoof_in(&mut rec_buf[..data_size as usize], peer_ip)
                .unwrap())
        }
    }

    fn spoof_in(&self, buf: &mut [u8], peer_ip: Ipv4Addr) -> Option<Vec<u8>> {
        let mut packet = MutableIpv4Packet::new(buf)?;

        let mut payload = packet.payload().to_owned().clone();
        self.spoof_ip_next_in(&mut payload, packet.get_source(), peer_ip);

        packet.set_destination(peer_ip);
        packet.set_payload(&payload);
        let ip_checksum = ipv4::checksum(&Ipv4Packet::new(packet.packet())?);
        packet.set_checksum(ip_checksum);

        Some(packet.packet().to_owned())
    }

    fn spoof_ip_next_in(
        &self,
        packet: &mut [u8],
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
    ) -> Option<()>;

    fn spoof_ip_next_out(
        &mut self,
        packet: &mut [u8],
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
    ) -> Option<()>;
}

pub trait Connection: Send {
    type SockType: RawSock;

    async fn send_to_remote_host(&mut self, packet: &mut [u8]) -> Result<()>;
    async fn recv_from_remote_host(&self) -> Result<Vec<u8>>;

    async fn handle_recv(&self, mut tls_writer: SecureWrite) -> Result<()> {
        info!("receiver running!");
        loop {
            let res = self.recv_from_remote_host().await?;
            info!("Sending to client, {res:?}");
            tls_writer.write_all(&res).await?;
        }
    }

    async fn handle_forward(&mut self, mut tls_reader: SecureRead) -> Result<()> {
        info!("forwarder running!");
        let mut buf = [0u8; MTU_SIZE];
        loop {
            let size = tls_reader.read(&mut buf).await?;

            info!("Forwarding");
            self.send_to_remote_host(&mut buf[..size]).await?;
        }
    }

    async fn init_from(packet: &mut [u8], stream: SecureStream) -> Result<()>;
    async fn run_forwarding(self, stream: SecureStream) -> Result<()>;
}
