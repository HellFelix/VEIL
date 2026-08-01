//! VEIL privileged operating system interaction.
//!
//! The tun device, a hand-written `NETLINK_ROUTE` client, and nftables ruleset
//! management. This is the **only** crate in the workspace permitted `unsafe`;
//! every other crate carries `#![forbid(unsafe_code)]`.
//!
//! Every foreign call goes through [`syscall!`], which is what makes "every
//! libc call site checks its return value" a property of the crate rather than
//! a convention. `tun`, `netlink` and `firewall` land at M2.

#![deny(unsafe_op_in_unsafe_fn)]

mod sys;

pub use sys::Errno;
#[doc(hidden)]
pub use sys::check;
