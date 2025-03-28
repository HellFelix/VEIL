// This is a miniature protocol used for setting client IPs based on DCHP

use std::{
    io::{self, Error, ErrorKind},
    net::{Ipv4Addr, SocketAddrV4},
};

use bincode;
use crc32fast;
use rand::{self, Rng};
use serde::{Deserialize, Serialize};

pub type SessionID = u32;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
pub enum Stage {
    Discover,
    Offer,
    Request,
    Acknowledge,
    Reject,
}
impl Stage {
    pub fn next_stage(self) -> io::Result<Self> {
        match self {
            Self::Discover => Ok(Self::Offer),
            Self::Offer => Ok(Self::Request),
            Self::Request => Ok(Self::Acknowledge),
            Self::Acknowledge => Err(Error::new(
                ErrorKind::Unsupported,
                format!("There is no next stage for the handshake after acknowledgement"),
            )),
            Self::Reject => Err(Error::new(
                ErrorKind::Unsupported,
                format!("The handshake cannot proceed, because it has been rejected"),
            )),
        }
    }
}

// TODO! Bincode error handling!
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
pub struct Handshake {
    address: Option<Ipv4Addr>,
    checksum: u32,
    session_id: SessionID,
    stage: Stage,
}
impl Handshake {
    /// Creates a message at the Discover stage with a new session id
    pub fn initial_handshake() -> Self {
        let mut res = Self {
            address: None,
            checksum: 0,
            session_id: rand::rng().random(),
            stage: Stage::Discover,
        };
        res.set_checksum();

        res
    }

    pub fn discovery_rejection(client_source_address: Ipv4Addr) -> Self {
        let mut res = Self {
            address: Some(client_source_address),
            checksum: 0,
            session_id: 0,
            stage: Stage::Reject,
        };
        res.set_checksum();

        res
    }

    /// Creates a rejection message for a rejection after a session ID has been accepted
    pub fn in_session_rejection(client_source_address: Ipv4Addr, session_id: SessionID) -> Self {
        let mut res = Self {
            address: Some(client_source_address),
            checksum: 0,
            session_id,
            stage: Stage::Reject,
        };
        res.set_checksum();

        res
    }

    pub fn is_rejection(&self) -> bool {
        self.stage == Stage::Reject
    }

    /// Consumes the current handshake state and
    /// advances the handshake to the next stage
    pub fn advance(self) -> io::Result<Self> {
        let mut res = Self {
            address: self.address,
            checksum: 0,
            session_id: self.session_id,
            stage: self.stage.next_stage()?,
        };
        res.set_checksum();

        Ok(res)
    }

    /// After advancing to Offer, the handshake needs to receive an address
    /// from the server
    pub fn set_offer(&mut self, addr: Ipv4Addr) {
        self.address = Some(addr);
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }

    pub fn to_bytes(self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    pub fn validate(&self, expected: Option<Self>) -> io::Result<()> {
        if match self.stage {
            Stage::Discover => self.validate_discovery(Self::discovery_validator()),
            Stage::Offer => self.validate_offer(unwrap_handshake(expected)?),
            _ => *self == unwrap_handshake(expected)?,
        } {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!("Handshake is invalid"),
            ))
        }
    }

    // This is a "dummy" that should be passed when validating a discovery. Because
    // the server has no
    const fn discovery_validator() -> Self {
        Self {
            address: None,
            checksum: 0,
            session_id: 0,
            stage: Stage::Discover,
        }
    }

    // Because thee server doesn't know the session id ahead of time, we cannot do a full check at
    // this stage
    fn validate_discovery(&self, expected: Self) -> bool {
        self.checksum == self.calculate_checksum() && self.stage == expected.stage
    }

    // Becaues the client doesn't know the expected value of the offer ahead of time, we can't do a
    // full check at this stage
    fn validate_offer(&self, expected: Self) -> bool {
        self.checksum == self.calculate_checksum()
            && self.stage == expected.stage
            && self.session_id == expected.session_id
    }

    pub fn get_addr(&self) -> io::Result<Ipv4Addr> {
        if let Some(addr) = self.address {
            Ok(addr)
        } else {
            Err(Error::new(
                ErrorKind::Other,
                format!("The handshake does not have an address at this stage"),
            ))
        }
    }

    pub fn get_session_id(&self) -> SessionID {
        self.session_id
    }

    fn set_checksum(&mut self) {
        self.checksum = self.calculate_checksum();
    }

    fn calculate_checksum(&self) -> u32 {
        let mut hasher = crc32fast::Hasher::new();

        hasher.update(&bincode::serialize(&self.stage).unwrap());
        hasher.update(&self.session_id.to_be_bytes());

        hasher.finalize()
    }
}

pub fn unwrap_handshake(value: Option<Handshake>) -> io::Result<Handshake> {
    if let Some(handshake) = value {
        Ok(handshake)
    } else {
        Err(Error::new(
            ErrorKind::InvalidData,
            format!("Expected handshake, found None"),
        ))
    }
}

pub struct Address {
    addr: Ipv4Addr,
    claimed: bool,
}
impl Address {
    pub fn claim(&mut self) -> io::Result<()> {
        if self.claimed {
            Err(Error::new(
                ErrorKind::AddrInUse,
                format!(
                    "Attempted to claim address {}, but it is already claimed",
                    self.addr
                ),
            ))
        } else {
            self.claimed = true;
            Ok(())
        }
    }

    pub fn unclaim(&mut self) -> io::Result<()> {
        if self.claimed {
            self.claimed = false;
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Attempted to unclaim address {}, but it is already unclaimed",
                    self.addr
                ),
            ))
        }
    }

    pub fn is_claimed(&self) -> bool {
        self.claimed
    }

    pub fn get_raw(&self) -> Ipv4Addr {
        self.addr
    }
}
impl From<Ipv4Addr> for Address {
    fn from(value: Ipv4Addr) -> Self {
        Self {
            addr: value,
            claimed: false,
        }
    }
}

pub struct AddrPool(Vec<Address>);
impl AddrPool {
    pub fn create() -> Self {
        Self(
            (1..=255)
                .map(|i| Ipv4Addr::new(10, 0, 0, i).into())
                .collect(),
        )
    }

    pub fn find_unclaimed(&self) -> io::Result<Ipv4Addr> {
        let mut addresses = self.0.iter();
        while let Some(addr) = addresses.next() {
            if !addr.is_claimed() {
                return Ok(addr.get_raw());
            }
        }
        Err(Error::new(
            ErrorKind::WouldBlock,
            format!("All addresses have been claimed!"),
        ))
    }

    /// Claim the selected address
    pub fn claim(&mut self, addr: Ipv4Addr) -> io::Result<()> {
        self.0[addr.octets()[3] as usize - 1].claim()?;
        Ok(())
    }

    /// Release the selected address so that it could be reused
    pub fn release(&mut self, addr: Ipv4Addr) -> io::Result<()> {
        self.0[addr.octets()[3] as usize - 1].unclaim()?;
        Ok(())
    }
}
