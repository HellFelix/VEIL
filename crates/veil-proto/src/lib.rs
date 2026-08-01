//! VEIL wire types.
//!
//! Control messages, their codec, and the minimal IP header reading described in
//! `plan.md` §5.5. Pure computation: no sockets, no async, no operating system,
//! so the whole crate is unit-testable and fuzzable without privileges.
//!
//! Populated at M3.

#![forbid(unsafe_code)]
