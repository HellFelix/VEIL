use libc::{c_char, c_short, ioctl, IFF_NO_PI, IFF_TUN, IFNAMSIZ, O_RDWR};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Result};
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

const TUN_DEVICE: &str = "/dev/net/tun";
const TUNSETIFF: libc::c_ulong = 0x400454ca; // from <linux/if_tun.h>

use crate::system::TunInterface;

pub const MTU_SIZE: usize = 9000;

#[repr(C)]
#[derive(Debug)]
struct Ifreq {
    ifr_name: [c_char; IFNAMSIZ],
    ifr_flags: c_short,
}

pub fn open_tun_interface(
    name_hint: Option<&str>,
    local_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
) -> Result<TunInterface> {
    // Open /dev/net/tun
    let fd = unsafe { libc::open(CString::new(TUN_DEVICE).unwrap().as_ptr(), O_RDWR) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Setup ifreq
    let mut ifr: Ifreq = unsafe { mem::zeroed() };

    if let Some(name) = name_hint {
        for (dst, src) in ifr.ifr_name.iter_mut().zip(name.as_bytes()) {
            *dst = *src as c_char;
        }
    }

    ifr.ifr_flags = (IFF_TUN | IFF_NO_PI) as c_short;

    // Call ioctl to create the interface
    let res = unsafe { ioctl(fd, TUNSETIFF, &ifr) };

    if res < 0 {
        return Err(io::Error::last_os_error());
    }

    let name = unsafe {
        std::ffi::CStr::from_ptr(ifr.ifr_name.as_ptr())
            .to_string_lossy()
            .into_owned()
    };

    Ok(TunInterface {
        fd,
        name,
        local_addr,
        peer_addr,
    })
}
