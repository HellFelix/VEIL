use std::net::IpAddr;

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Encode, Decode)]
pub enum Command {
    Connect(String),
    Disconnect,

    Config,
}

#[derive(Serialize, Deserialize, Encode, Decode)]
enum Config {
    set(RoutingRule),
    unset(RoutingRule),
}

#[derive(Serialize, Deserialize, Encode, Decode)]
enum RoutingRule {
    Host(IpAddr),
    All,
}
