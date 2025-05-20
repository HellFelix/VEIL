use std::net::IpAddr;

use bincode::{Decode, Encode};
use log::Level;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Encode, Decode, Debug)]
pub enum Command {
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
    Connect(ServerAddr),
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
    Config(ConfigRule),

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

#[derive(Serialize, Deserialize, Encode, Decode, Debug)]
pub enum ServerAddr {
    Default,
    Configured(String),
    Override(IpAddr, u16),
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug)]
pub enum Log {
    Show,
    Get,
    Set(LogLevel),
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug)]
pub enum ConfigRule {
    Route(RouteOpt, RoutingRule),
    Server(ServerOpt),
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug)]
pub enum ServerOpt {
    Add(String, IpAddr),
    Remove(String),
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug)]
pub enum RouteOpt {
    Set,
    Unset,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug)]
pub enum RoutingRule {
    Host(IpAddr, Permission),
    All(Permission),
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug)]
pub enum Permission {
    Allow,
    Block,
}
