use pest::Parser;
use pest_derive::Parser;
use std::collections::HashMap;
use std::error::Error;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::{fs, io};

use client::ServerConf;

#[derive(Parser)]
#[grammar = "conf_grammar.pest"] // path to your .pest file
struct ClientConfigParser;

#[derive(Debug)]
pub struct ClientConf {
    pub servers: HashMap<String, ServerConf>,
    pub route: RouteConf,
}

#[derive(Debug)]
pub struct HostConf {
    ipv: u8,
    address: String,
}

#[derive(Debug)]
pub struct RouteConf {
    route_all: bool,
    exclude_hosts: Vec<HostConf>,
    include_hosts: Vec<HostConf>,
}

pub fn extract_conf() -> Result<ClientConf, Box<dyn Error>> {
    let config_str = fs::read_to_string("/etc/veil/veil.conf")?;
    parse_conf(&config_str)
}

fn parse_conf(input: &str) -> Result<ClientConf, Box<dyn Error>> {
    let config_pair = ClientConfigParser::parse(Rule::config, input)?
        .next()
        .ok_or("Missing root config block")?;

    let mut servers: HashMap<String, ServerConf> = HashMap::new();
    let mut route_all = false;
    let mut exclude_hosts = Vec::new();
    let mut include_hosts = Vec::new();

    for section in config_pair.into_inner() {
        if section.as_rule() != Rule::block {
            continue;
        }

        let mut parts = section.into_inner();
        let section_name = parts.next().ok_or("Expected section name")?.as_str();

        match section_name {
            "servers" => {
                for server_block in parts {
                    if server_block.as_rule() != Rule::block {
                        continue;
                    }

                    let mut inner = server_block.into_inner();
                    let server_name = inner
                        .next()
                        .ok_or("Expected server name")?
                        .as_str()
                        .to_string();

                    let mut address = None;
                    let mut ipv = None;
                    let mut port = None;

                    for pair in inner {
                        if pair.as_rule() != Rule::pair {
                            continue;
                        }

                        let mut kv = pair.into_inner();
                        let key = kv.next().ok_or("Missing key")?.as_str();
                        let value = kv.next().ok_or("Missing value")?.as_str();

                        match key {
                            "address" => address = Some(value.to_string()),
                            "ipv" => ipv = Some(value.parse()?),
                            "port" => port = Some(value.parse()?),
                            _ => {}
                        }
                    }

                    let finalized_addr = match ipv.ok_or("Missing server ipv")? {
                        4 => IpAddr::V4(Ipv4Addr::from_str(
                            &address.ok_or("Missing server address")?,
                        )?),
                        6 => IpAddr::V6(Ipv6Addr::from_str(
                            &address.ok_or("Missing server address")?,
                        )?),
                        _ => Err(io::Error::new(ErrorKind::InvalidData, "Invalid ipv"))?,
                    };

                    servers.insert(
                        server_name,
                        ServerConf {
                            address: finalized_addr,
                            port: port.ok_or("Missing server port")?,
                        },
                    );
                }
            }

            "route" => {
                for route_item in parts {
                    match route_item.as_rule() {
                        Rule::pair => {
                            let mut inner = route_item.into_inner();
                            let key = inner.next().ok_or("Missing key")?.as_str();
                            let value = inner.next().ok_or("Missing value")?.as_str();
                            if key == "route-all" {
                                route_all = match value {
                                    "true" => true,
                                    "false" => false,
                                    _ => return Err("Invalid boolean value for route-all".into()),
                                };
                            }
                        }

                        Rule::block => {
                            let mut inner = route_item.into_inner();
                            let name = inner.next().ok_or("Missing route block name")?.as_str();

                            let target = match name {
                                "exclude-routes" => &mut exclude_hosts,
                                "include-route" => &mut include_hosts,
                                _ => continue,
                            };

                            for host_block in inner {
                                if host_block.as_rule() != Rule::block {
                                    continue;
                                }

                                let mut host = HostConf {
                                    ipv: 0,
                                    address: String::new(),
                                };

                                for field in host_block.into_inner().skip(1) {
                                    if field.as_rule() == Rule::pair {
                                        let mut inner = field.into_inner();
                                        let key =
                                            inner.next().ok_or("Missing host field key")?.as_str();
                                        let value = inner
                                            .next()
                                            .ok_or("Missing host field value")?
                                            .as_str();
                                        match key {
                                            "ipv" => host.ipv = value.parse()?,
                                            "address" => host.address = value.to_string(),
                                            _ => {}
                                        }
                                    }
                                }

                                target.push(host);
                            }
                        }

                        _ => {}
                    }
                }
            }

            _ => {}
        }
    }

    Ok(ClientConf {
        servers,
        route: RouteConf {
            route_all,
            exclude_hosts,
            include_hosts,
        },
    })
}
