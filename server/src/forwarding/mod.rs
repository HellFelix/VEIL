use std::{ffi::c_void, io, marker::PhantomData, net::Ipv4Addr, ptr};

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

use crate::SERVER_CONFIG;
use vpn_core::{system::MTU_SIZE, Error, Result};

mod tcp;
pub use tcp::{RawTcpSock, TcpConnection};

mod icmp;
pub use icmp::{IcmpConnection, RawIcmpSock};

mod udp;
pub use udp::{RawUdpSock, UdpConnection};

#[derive(Clone, Copy)]
pub struct AbstractSock {
    dst: sockaddr_in,
    sock_r: i32,
}
impl AbstractSock {
    fn send(&self, spoofed_packet: Vec<u8>) -> Result<()> {
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

pub struct SockOpts {
    eph_port: Option<u16>,
}

pub trait SockStateType: Clone + Copy + Sized {
    fn with_opts(abs: AbstractSock, opts: SockOpts) -> Result<Self>;

    fn degenerate(&self) -> AbstractSock;
}

#[derive(Clone, Copy)]
pub struct StatefulSock {
    abs: AbstractSock,
    eph_port: Option<u16>,
    spoofed_eph_port: u16,
}
impl SockStateType for StatefulSock {
    fn with_opts(abs: AbstractSock, opts: SockOpts) -> Result<Self> {
        let spoofed_eph_port = rand::rng().random_range(45000..54000);

        Ok(Self {
            abs,
            eph_port: opts.eph_port,
            spoofed_eph_port,
        })
    }

    fn degenerate(&self) -> AbstractSock {
        self.abs
    }
}

#[derive(Clone, Copy)]
pub struct StatelessSock {
    abs: AbstractSock,
}
impl SockStateType for StatelessSock {
    fn with_opts(abs: AbstractSock, opts: SockOpts) -> Result<Self> {
        Ok(Self { abs })
    }

    fn degenerate(&self) -> AbstractSock {
        self.abs
    }
}

pub trait RawSock<T: SockStateType>: Clone + Copy + Sized + From<T> {
    const IPPROTO: i32;

    fn get_abstract(&self) -> T;

    //TODO: Do error handling from kernel results
    fn init(host_addr: Ipv4Addr, opts: SockOpts) -> Result<Self> {
        //TODO: Set the range from the systems available ports

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

            Ok(Self::from(T::with_opts(
                AbstractSock { dst, sock_r },
                opts,
            )?))
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
        self.get_abstract().degenerate().send(packet)
    }

    fn spoof_recv(&self, peer_ip: Ipv4Addr, dst_addr: Ipv4Addr) -> Result<Vec<u8>> {
        let mut rec_buf = [0u8; MTU_SIZE];
        unsafe {
            let data_size = recvfrom(
                self.get_abstract().degenerate().sock_r,
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
            if let Some(res) = self.spoof_in(&mut rec_buf[..data_size as usize], peer_ip, dst_addr)
            {
                Ok(res)
            } else {
                Err(Error::new(
                    vpn_core::ErrorKind::Dropped,
                    format!("Packet dropped due to traffic rule"),
                ))
            }
        }
    }

    fn spoof_in(&self, buf: &mut [u8], peer_ip: Ipv4Addr, dst_addr: Ipv4Addr) -> Option<Vec<u8>> {
        let mut packet = MutableIpv4Packet::new(buf)?;

        // filter traffic not meant the client
        if packet.get_source() != dst_addr {
            info!("Packet is destined for {}", packet.get_destination());
            return None;
        }
        //

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
        &self,
        packet: &mut [u8],
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
    ) -> Option<()>;
}

pub trait Connection<T: SockStateType, S: RawSock<T>, P: Packet>:
    Send + Sync + Copy + From<AbstractConn<T, S>>
{
    fn send_to_remote_host(&mut self, packet: &mut [u8]) -> Result<()>;
    fn recv_from_remote_host(&self) -> Result<Vec<u8>>;

    fn get_conn_opts(packet: &Ipv4Packet) -> Option<SockOpts>;

    fn create_from_packet(packet: &Ipv4Packet) -> Result<Self> {
        let sock = S::init(
            packet.get_destination(),
            Self::get_conn_opts(packet).unwrap(),
        )?;

        Ok(AbstractConn {
            sock,
            _marker: PhantomData,
            self_addr: SERVER_CONFIG.get_ipv4_addr(),
            peer_addr: packet.get_source(),
            dst_addr: packet.get_destination(),
        }
        .into())
    }
}

#[derive(Clone, Copy)]
pub struct AbstractConn<T: SockStateType, S: RawSock<T>> {
    sock: S,
    _marker: PhantomData<T>,
    self_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
}

pub enum ConnectionType {
    StateFul,
    StateLess,
}
