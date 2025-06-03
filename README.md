# VEIL - Verified Encrypted Internet Link

## Installation
**Note: The server runs using raw sockets from userspace, which is generally disallowed on MacOS and Windows.** 
It may be possible to unlock raw sockets to allow the server crate to run on these systems, although realistically, 
running on linux is currently the only viable option.

### Recommended
When using Linux or macOS, the easiest method of installation is via the latest release.

### Manual
Both client and server system can be installed manually by cloning this repository.
``git clone git@github.com:HellFelix/VEIL.git && cd VEIL``
Then build the necessary crates. Note that the server and client systems are built independently
``./build.sh server``
``./build.sh client``


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

### Client

## License

This project is distributed under the **VEIL Public Access License (v1.0)**.

- ✅ **Permitted:** Personal, non-commercial use by individuals. You may view, modify, and share the source code for private use.
- ❌ **Prohibited:** Any use by companies, organizations, institutions, or government entities without a commercial license. Sublicensing and public/cloud deployment are also not permitted.

### 🏢 Are you a company or organization?

Commercial and institutional use is welcome, but a separate license is required.

Please refer to **Section 2.1 of the VEIL Public Access License (v1.0)** for instructions on how to request a commercial license. The Licensor is open to granting licenses free of charge in many cases.

📬 Contact: [felix.hellborg.la@gmail.com](mailto:felix.hellborg.la@gmail.com) · [GitHub: HellFelix](https://github.com/HellFelix)
