# VEIL - Verified Encrypted Internet Link

> **VEIL v2 is under construction.** The v1 implementation described below has
> been removed; it is preserved at the git tag `v1-final` and can be recovered
> with `git checkout v1-final`. The v2 design and its milestones are in
> [`plan.md`](./plan.md), and the installation and usage instructions here will
> be rewritten at M14. Nothing below the quick start currently builds.

## Quick start (development)

> Provisional, and covers the control plane only: two machines authenticate each
> other and exchange configuration. **No traffic is tunnelled yet** — the tun
> device and packet forwarding arrive at M2 and M5. Superseded at M14.

Nothing here needs root or any capability, because there is no tun device yet.

### Install

On both machines, from a clone of this repository:

```sh
# server
./scripts/install.sh --server

# client
./scripts/install.sh --client
```

This builds in release mode and installs everything under `/etc/veil`: the
three binaries in `bin/`, a `private.key` for that machine, and the config for
its role. It prints that machine's public key. Re-running it never replaces an
existing key or config.

Pass `--owner "$USER"` to run the daemons without `sudo`, or `--dir PATH` to
install somewhere else. Add `/etc/veil/bin` to your `PATH`.

### Enrol the client

Copy the client's public key to the server and add it to the whitelist:

```sh
veil-ctl peer add laptop ed25519:... --ipv4 10.44.0.2 --allowed 0.0.0.0/0
veil-ctl peer list
```

Only the public half ever leaves the client. `veil-ctl peer` preserves the
comments in `peers.toml`, so the file stays hand-editable.

Then fill in `server` and `server_key` in the client's `/etc/veil/client.toml`,
using the server's address and the key its install printed.

### Run

```sh
veil-ctl serve      # on the server
veil-ctl connect    # on the client
```

The client ends at `authorized by the server`. Every setting can be overridden
on the command line, so `veil-ctl serve --listen 127.0.0.1:51820` needs no
config file at all.

**QUIC runs over UDP.** If a firewall is running, open **UDP** 51820, not TCP.

### Revoke

```sh
veil-ctl peer set laptop --enabled false   # keep the entry as a record
veil-ctl peer remove laptop                # delete it
```

Both take effect when `veild` restarts; live reload on `SIGHUP` arrives at M3.

### Uninstall

```sh
./scripts/uninstall.sh
```

Removes `/etc/veil` entirely, including the private key, after confirmation.

## Installation
**Note: The server runs using raw sockets from userspace, which is generally disallowed on MacOS and Windows.** 
It may be possible to unlock raw sockets to allow the server crate to run on these systems, although realistically, 
running on linux is currently the only viable option.

### Manual
Both client and server system can be installed manually by cloning this repository.
``git clone git@github.com:HellFelix/VEIL.git && cd VEIL``
Then build the necessary crates. Note that the server and client systems are built independently
```
./build.sh server
```
```
./build.sh client
```
Having built the client crates, the ctl tool and systemd service can then be installed using the installation script
```
./client_install.sh
```
Similarly, these tools can be uninstalled using
```
./client_uninstall.sh
```

### Certificates
VEIL operates on CA certificates, using [rustls](https://crates.io/crates/rustls) for authentication and safe
client-server communication.

#### Recommended setup:
- Generate root- and server certificates on the server-side side using the `crypt-setup.sh` script.
- When adding a new client, generate a new client certificate on the server-side using the `gen-client-crypt.sh` 
script and copy certificates to the client machine using a safe transfer tool such as `scp`. Note that the client
system requires the public root and server certificates, along with its own certificate key.

## System Overview
**VEIL** is a layer 3 VPN, capturing IP packets on the network layer (layer 3) using TUN (UTUN on macOS). 
Upon connecting to a server, a TLS connection is established, followed by a DHCP-like four way handshake, where
the client and server agree upon a session ID and an internal IP address for the client (172.16.x.x by default). By default,
the server's internal IP address will be 172.16.0.1, which can be pinged directly from the client because the TUN/UTUN interface
is set up to serve `CLIENT_INTERNAL -> SERVER_INTERNAL`. Thus, after authentication, one might ping the server using
```ping SERVER_INTERNAL```

### Server
The machine running the server program acts as a "dumb tunnel", forwarding packets from trusted client devices (currently supports
TCP, UDP, and ICMP). See [server documentation](./server/README.md) for details on how the program works.

### Client
Running the client service on a device will allow the device to connect to another device running the server. Having connected
to a server, one must then route traffic through the TUN/UTUN interface which is setup during connection. The logs will 
show what the interface is called. If everything was run correctly, you will see the following:
```
[INFO]: Successfully initialized INTERFACE_NAME interface
```

Then, using the `route` command, one can route traffic through the new interface. Note that this can be done for individual 
hosts or globaly depending on use case.
After routing is correctly set up, traffic will now go through the tunnel.

## License

This project is distributed under the **VEIL Public Access License (v1.0)**.

- ✅ **Permitted:** Personal, non-commercial use by individuals. You may view, modify, and share the source code for private use.
- ❌ **Prohibited:** Any use by companies, organizations, institutions, or government entities without a commercial license. Sublicensing and public/cloud deployment are also not permitted.

### 🏢 Are you a company or organization?

Commercial and institutional use is welcome, but a separate license is required.

Please refer to **Section 2.1 of the VEIL Public Access License (v1.0)** for instructions on how to request a commercial license. The Licensor is open to granting licenses free of charge in many cases.

📬 Contact: [felix.hellborg.la@gmail.com](mailto:felix.hellborg.la@gmail.com) · [GitHub: HellFelix](https://github.com/HellFelix)
