// This is a miniature protocol used for setting client IPs based on DCHP

use std::{
    io::{self, Error, ErrorKind},
    net::{Ipv4Addr, SocketAddrV4},
};

use bincode;
use crc32fast;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
pub enum Stage {
    Discover,
    Offer(Option<Ipv4Addr>),
    Request(Ipv4Addr),
    Acknowledge(Ipv4Addr),
}
impl Stage {
    /// Returns the wrapped address for the stages wheere validation is possible.
    pub fn get_addr(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Discover => None,
            Self::Offer(addr) => *addr,
            Self::Request(addr) => Some(*addr),
            Self::Acknowledge(addr) => Some(*addr),
        }
    }

    pub fn validate(&self, expected: Self) -> io::Result<()> {
        if let (Self::Offer(_), Self::Offer(_)) = (self, expected) {
            Ok(())
        } else if self == &expected {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!("Stage mismatch"),
            ))
        }
    }
}

// TODO! Bincode error handling!
#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    stage: Stage,
    source: SocketAddrV4,
    destination: SocketAddrV4,
    checksum: u32,
}
impl Message {
    pub fn new(stage: Stage, source: SocketAddrV4, destination: SocketAddrV4) -> Self {
        let mut res = Self {
            stage,
            source,
            destination,
            checksum: 0,
        };

        let checksum = res.calculate_checksum();
        res.checksum = checksum;

        res
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }

    pub fn to_bytes(self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    pub fn validate(
        &self,
        source: SocketAddrV4,
        destination: SocketAddrV4,
        expected_stage: Stage,
    ) -> io::Result<()> {
        if self.checksum == self.calculate_checksum() {
            if source == self.source && destination == self.destination {
                self.stage.validate(expected_stage)?;
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Incorrect source or destination IP"),
                ))
            }
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!("Calculated checksum does not match the received checksum!"),
            ))
        }
    }

    pub fn get_addr(&self) -> io::Result<Ipv4Addr> {
        if let Some(addr) = self.stage.get_addr() {
            Ok(addr)
        } else {
            Err(Error::new(
                ErrorKind::Other,
                format!("The current stage has no address"),
            ))
        }
    }

    fn calculate_checksum(&self) -> u32 {
        let mut hasher = crc32fast::Hasher::new();

        hasher.update(&bincode::serialize(&self.stage).unwrap());
        hasher.update(&bincode::serialize(&self.source.ip()).unwrap());
        hasher.update(&bincode::serialize(&self.source.port().to_be_bytes()).unwrap());
        hasher.update(&bincode::serialize(&self.destination.ip()).unwrap());
        hasher.update(&bincode::serialize(&self.destination.port().to_be_bytes()).unwrap());

        hasher.finalize()
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
