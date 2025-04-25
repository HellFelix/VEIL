use std::os::fd::RawFd;
use std::process;
use std::{io, net::Ipv4Addr};

use log::*;

use libc::{c_void, close, poll, pollfd, read, ssize_t, write, POLLIN};

use crate::utils::error::Result;

mod unix;

#[cfg(target_os = "macos")]
use unix::macos::open_raw_interface;
#[cfg(target_os = "macos")]
pub use unix::macos::MTU_SIZE;

#[cfg(target_os = "linux")]
use unix::linux::open_tun_interface;
#[cfg(target_os = "linux")]
pub use unix::linux::MTU_SIZE;

pub struct TunInterface {
    pub fd: RawFd,
    pub name: String,
    pub local_addr: Ipv4Addr,
    pub peer_addr: Ipv4Addr,
}
impl TunInterface {
    pub fn read(&self, buf: &mut [u8; MTU_SIZE]) -> Result<Option<ssize_t>> {
        unsafe {
            let mut fds = [pollfd {
                fd: self.fd,
                events: POLLIN,
                revents: 0,
            }];

            let result = poll(fds.as_mut_ptr(), 1, 1);

            if result < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            if fds[0].revents & POLLIN != 0 {
                let res = read(self.fd, buf.as_mut_ptr() as *mut c_void, MTU_SIZE);
                Ok(if res > 0 { Some(res) } else { None })
            } else {
                Ok(None)
            }
        }
    }

    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        unsafe {
            if write(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) < 0 {
                return Err(io::Error::last_os_error().into());
            } else {
                Ok(())
            }
        }
    }
}
impl Drop for TunInterface {
    fn drop(&mut self) {
        info!("Closing the {} interface.", self.name);
        unsafe {
            close(self.fd);
        }
    }
}

pub fn setup(interface_ip: Ipv4Addr, peer_ip: Ipv4Addr) -> Result<TunInterface> {
    #[cfg(target_os = "linux")]
    let interface = open_tun_interface(Some("tun0"), interface_ip, peer_ip)?;
    #[cfg(target_os = "macos")]
    let interface = unsafe { open_raw_interface(interface_ip, peer_ip)? };

    info!("Successfully initialized {} interface", interface.name);

    #[cfg(target_os = "linux")]
    process::Command::new("ifconfig")
        .args([
            interface.name.clone(),
            format!("{interface_ip}"),
            String::from("pointopoint"),
            format!("{peer_ip}"),
            String::from("up"),
        ])
        .status()
        .unwrap();
    #[cfg(target_os = "macos")]
    process::Command::new("ifconfig")
        .args([
            interface.name.clone(),
            format!("{interface_ip}"),
            format!("{peer_ip}"),
            String::from("up"),
        ])
        .status()
        .unwrap();
    info!("Successfully initialized Tunnel endpoint");
    info!("Interface IP is set to {interface_ip}");
    info!("Peer IP is set to {peer_ip}");

    Ok(interface)
}
