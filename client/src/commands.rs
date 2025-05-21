use std::net::IpAddr;

use bincode;
use log::Level;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Command<'a> {
    /// Connect to server at provided address
    /// `veil connect -o {address} {port}`
    /// `veil connect --override {address} {port}`
    ///
    /// Connect to server from configured servers
    /// `veil connect -n {name}`
    /// `veil connect --name {name}`
    ///
    /// Connect to server with address specified in veil.conf
    /// `veil connect`
    #[serde(borrow)]
    Connect(ServerAddr<'a>),
    /// Disconnect form current server
    /// Graceful disconnect - waits for server acknowledgement
    /// `veil disconnect`
    ///
    /// Client shuts down without sending disconnect notify or TLS close notify
    /// `veil disconnect -f`
    /// `veil disconnect --force`
    Disconnect(bool),

    /// Display client logs
    /// `veil log show`
    ///
    /// Set log level
    /// veil log set {error|warn|info|debug|trace}
    ///
    /// Get log level
    /// veil log get
    Log(Log),

    /// Change config rules
    /// This can also be changed manually by writing them to veil.conf
    ///
    /// `veil config server add {name} {address}`
    /// `veil config server remove {name}`
    ///
    /// `veil config route set -a block`
    /// `veil config route set --all block`
    /// `veil config route set -h {address} allow `
    /// `veil config route set --host {address} allow`
    ///
    /// `veil config route unset -h {address}`
    /// `veil config route unset --host {address}`
    Config(ConfigRule<'a>),

    /// Display usage
    /// `veil`
    /// `veil -h`
    /// `veil --help`
    Help,
    /// Display version
    /// `veil -v`
    /// `veil --version`
    Version,
}

impl<'a> Command<'a> {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes<'b: 'a>(input: &'b [u8]) -> Self {
        bincode::deserialize(input).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum ServerAddr<'a> {
    Default,
    Configured(&'a str),
    Override(IpAddr, u16),
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Log {
    Show,
    Get,
    Set(LogLevel),
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum ConfigRule<'a> {
    Route(RouteOpt, RoutingRule),
    #[serde(borrow)]
    Server(ServerOpt<'a>),
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum ServerOpt<'a> {
    Add(&'a str, IpAddr),
    Remove(&'a str),
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum RouteOpt {
    Set,
    Unset,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum RoutingRule {
    Host(IpAddr, Permission),
    All(Permission),
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Permission {
    Allow,
    Block,
}
