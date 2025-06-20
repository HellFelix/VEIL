use std::{
    ffi::{CStr, CString},
    io,
    mem::{self, zeroed},
    net::Ipv4Addr,
    os::fd::RawFd,
};

use libc::{
    c_char, c_void, close, connect, ctl_info, getsockopt, ioctl, poll, pollfd, read, sockaddr,
    sockaddr_ctl, socklen_t, ssize_t, write, AF_SYSTEM, CTLIOCGINFO, IFNAMSIZ, PF_SYSTEM, POLLIN,
    SOCK_DGRAM, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
};

use crate::system::TunInterface;
use crate::utils::error::Result;

pub const MTU_SIZE: usize = 9000;

pub unsafe fn open_raw_interface(
    local_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
) -> Result<TunInterface> {
    // 1. Create the system socket
    let fd = libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }

    // 2. Prepare control info to resolve "com.apple.net.utun_control"
    let mut info: ctl_info = zeroed();
    info.ctl_id = 0;
    info.ctl_name = [0; 96];

    let name = CString::new("com.apple.net.utun_control").unwrap();
    for (i, b) in name.as_bytes_with_nul().iter().enumerate() {
        info.ctl_name[i] = *b as c_char;
    }

    let ioctl_result = unsafe { ioctl(fd, CTLIOCGINFO, &mut info) };
    if ioctl_result < 0 {
        return Err(io::Error::last_os_error().into());
    }

    // 3. Request dynamic assignment (sc_unit = 0)
    let mut addr: sockaddr_ctl = zeroed();
    addr.sc_reserved = [0; 5];
    addr.sc_len = mem::size_of::<sockaddr_ctl>() as u8;
    addr.sc_family = AF_SYSTEM as u8;
    addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0; // Let the system pick the next available utun

    let connect_result = unsafe {
        connect(
            fd,
            &addr as *const _ as *const sockaddr,
            mem::size_of::<sockaddr_ctl>() as u32,
        )
    };

    if connect_result < 0 {
        return Err(io::Error::last_os_error().into());
    }

    let mut ifname_buf = [0u8; IFNAMSIZ];
    let get_sock_res = getsockopt(
        fd,
        SYSPROTO_CONTROL,
        UTUN_OPT_IFNAME,
        ifname_buf.as_mut_ptr() as *mut c_void,
        &mut (IFNAMSIZ as socklen_t),
    );
    if get_sock_res < 0 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(TunInterface {
        fd,
        name: CStr::from_ptr(ifname_buf.as_ptr() as *const c_char)
            .to_str()
            .unwrap()
            .to_string(),
        local_addr,
        peer_addr,
    })
}
