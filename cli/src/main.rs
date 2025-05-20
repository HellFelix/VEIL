use std::{
    env::{self, Args},
    io::{self, Error, ErrorKind, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::net::UnixStream,
    str::FromStr,
};

use bincode::config;
use client::commands::*;

fn main() {
    match try_parse() {
        Ok(cmd) => send_to_service(cmd),
        Err(e) => println!("{e}"),
    }
}

fn try_parse() -> io::Result<Command> {
    let mut args = env::args();
    args.next();

    let cmd = if let Some(action) = args.next() {
        match &action[..] {
            "connect" => Command::Connect(parse_connect(args)?),
            "disconnect" => Command::Disconnect(parse_disconnect(args)?),
            "log" => Command::Log(parse_log(args)?),
            "config" => Command::Config(parse_config(args)?),

            "-h" => Command::Help,
            "--help" => Command::Help,

            "-v" => Command::Version,
            "--version" => Command::Version,
            _ => {
                unimplemented!()
            }
        }
    } else {
        unimplemented!()
    };

    Ok(cmd)
}

fn parse_connect(mut args: Args) -> io::Result<ServerAddr> {
    let res = if let Some(flag) = args.next() {
        match &flag[..] {
            "-o" => Ok(ServerAddr::Override(
                get_addr(args.next().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Address was not provided"),
                ))?)?,
                args.next()
                    .ok_or(Error::new(
                        ErrorKind::InvalidInput,
                        format!("Port was not provided"),
                    ))?
                    .parse::<u16>()
                    .expect("Parsing failed"),
            )),
            "--override" => Ok(ServerAddr::Override(
                get_addr(args.next().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Address was not provided"),
                ))?)?,
                args.next()
                    .ok_or(Error::new(
                        ErrorKind::InvalidInput,
                        format!("Port was not provided"),
                    ))?
                    .parse::<u16>()
                    .expect("Parsing failed"),
            )),

            "-n" => Ok(ServerAddr::Configured(args.next().ok_or(Error::new(
                ErrorKind::InvalidInput,
                format!("Missing server name"),
            ))?)),
            "--name" => Ok(ServerAddr::Configured(args.next().ok_or(Error::new(
                ErrorKind::InvalidInput,
                format!("Missing server name"),
            ))?)),
            a => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid argument {a}"),
            )),
        }
    } else {
        Ok(ServerAddr::Default)
    };

    // Next should be none
    match args.next() {
        Some(a) => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid argument {a}"),
        )),
        None => res,
    }
}
fn get_addr(addr: String) -> io::Result<IpAddr> {
    if let Ok(res) = Ipv4Addr::from_str(&addr) {
        return Ok(IpAddr::V4(res));
    } else if let Ok(res) = Ipv6Addr::from_str(&addr) {
        return Ok(IpAddr::V6(res));
    } else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Address does not match ipv4 or ipv6 format"),
        ));
    }
}

fn parse_disconnect(mut args: Args) -> io::Result<bool> {
    let res = if let Some(flag) = args.next() {
        match &flag[..] {
            "-f" => Ok(true),
            "--force" => Ok(true),
            a => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid argument {a}"),
            )),
        }
    } else {
        Ok(false)
    };

    match args.next() {
        Some(a) => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid argument {a}"),
        )),
        None => res,
    }
}

fn parse_log(mut args: Args) -> io::Result<Log> {
    let res = if let Some(action) = args.next() {
        match &action[..] {
            "show" => Ok(Log::Show),
            "get" => Ok(Log::Get),
            "set" => Ok(Log::Set(parse_log_level(args.next().ok_or(
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Missig log level for 'veil log set'"),
                ),
            )?)?)),
            a => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid log action '{a}'"),
            )),
        }
    } else {
        Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Missing action for command 'veil log'"),
        ))
    };
    match args.next() {
        Some(a) => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid argument {a}"),
        )),
        None => res,
    }
}
fn parse_log_level(arg: String) -> io::Result<LogLevel> {
    match &arg[..] {
        "error" => Ok(LogLevel::Error),
        "warn" => Ok(LogLevel::Warn),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        "trace" => Ok(LogLevel::Trace),
        l => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Log level {l} not recognized"),
        )),
    }
}

fn parse_config(mut args: Args) -> io::Result<ConfigRule> {
    if let Some(target) = args.next() {
        match &target[..] {
            "server" => Ok(ConfigRule::Server(parse_server_conf(args)?)),
            "route" => Ok(ConfigRule::Route(
                parse_route_opt(args.next().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Missing action for route config"),
                ))?)?,
                parse_route_rule(args)?,
            )),
            a => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid config target '{a}'"),
            )),
        }
    } else {
        Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Missing target for config"),
        ))
    }
}
fn parse_server_conf(mut args: Args) -> io::Result<ServerOpt> {
    if let Some(action) = args.next() {
        match &action[..] {
            "add" => Ok(ServerOpt::Add(
                args.next().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Missing server name"),
                ))?,
                get_addr(args.next().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Missing server name"),
                ))?)?,
            )),
            "remove" => Ok(ServerOpt::Remove(args.next().ok_or(Error::new(
                ErrorKind::InvalidInput,
                format!("Missing server name"),
            ))?)),
            a => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid server config action '{a}'"),
            )),
        }
    } else {
        Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Missing action for server config"),
        ))
    }
}
fn parse_route_opt(action: String) -> io::Result<RouteOpt> {
    match &action[..] {
        "set" => Ok(RouteOpt::Set),
        "unset" => Ok(RouteOpt::Unset),
        a => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid route config action '{a}'"),
        )),
    }
}
fn parse_route_rule(mut args: Args) -> io::Result<RoutingRule> {
    if let Some(flag) = args.next() {
        match &flag[..] {
            "-a" => Ok(RoutingRule::All(parse_permission(args.next().ok_or(
                Error::new(ErrorKind::InvalidInput, format!("Missing route permission")),
            )?)?)),
            "--all" => Ok(RoutingRule::All(parse_permission(args.next().ok_or(
                Error::new(ErrorKind::InvalidInput, format!("Missing route permission")),
            )?)?)),

            "-h" => Ok(RoutingRule::Host(
                get_addr(args.next().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Address was not provided"),
                ))?)?,
                parse_permission(args.next().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Missing route permission"),
                ))?)?,
            )),
            "--host" => Ok(RoutingRule::Host(
                get_addr(args.next().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Address was not provided"),
                ))?)?,
                parse_permission(args.next().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Missing route permission"),
                ))?)?,
            )),
            a => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid routing flag '{a}'"),
            )),
        }
    } else {
        Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Missing routing flag"),
        ))
    }
}
fn parse_permission(arg: String) -> io::Result<Permission> {
    match &arg[..] {
        "block" => Ok(Permission::Block),
        "allow" => Ok(Permission::Allow),
        a => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid permission '{a}'"),
        )),
    }
}

fn send_to_service(cmd: Command) {
    let mut stream = UnixStream::connect("/tmp/veil.sock")
        .expect("Failed to connect to unix socket. Is client service running?");

    let config = config::standard();
    let encoded: Vec<u8> = bincode::encode_to_vec(&cmd, config).unwrap();
    println!("{encoded:?}");

    stream
        .write_all(&encoded)
        .expect("Failed to write to unix socket. Is client running?");
}
