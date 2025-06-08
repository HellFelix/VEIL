# VEIL Server

The veil server acts as a central outward-facing entry node that allows clients to 
send and receive packets without disclosing their IP addresses. Instead, all traffic will
be disguised as the servers address.

## Structure
The following flow chart describes how the server handles connections from a client

```
              ----------------------------
              | Client                   |
              |                          |
              |                          |
              |                          |
              ----------------------------
                      |          ^
     Outbound Traffic |          | Inbound Traffic
                      |          |
----------------------|----------|-----------------------
| Server              |          |                      |
| --------------------|----------|--------------------- |
| | Client Handler    |          |                    | |
| |                   v          |                    | |
| |      -----------------     -----------------      | |
| |      | Forwarder     |     | Responder     |      | |
| |      |               |     |               |      | |
| |      -----------------     -----------------      | |
| |       |           |          ^          ^         | |
| |       |           |          |          |         | |
| |       v           v          |          |         | |
| |    ---------   ---------  ---------   ---------   | |
| |    | Out-  |   | Out-  |  | In-   |   | In-   |   | |
| |    | link  |   | link  |  | link  |   | link  |   | |
| |    ---------   ---------  ---------   ---------   | |
| |                   |           ^                   | |
| --------------------|-----------|-------------------- |
----------------------|-----------|----------------------
                      |           |
      Spoofed Traffic |           | Incoming Traffic
                      v           |
              ----------------------------
              | Remote Host              |
              |                          |
              |                          |
              |                          |
              ----------------------------
```

## Client Handler
Upon a successful connection to the server, a client handler is set up which listens to outbound 
traffic from a specific client. If a packet is recognized as a part of a previously 
existing connection, it is sent to the corresponding out-link, if not, a new out-link
is created to serve the connection. This allows the handler to serve multiple connections.

**Note** that the representation above does not apply to stateless connections such as ICMP.
In the case of such a packet, the handler will simply forward the packet after having spoofed the
IP address.

### Forwarder
The forwarder is responsible for keeping track of connections and sending packets to the correct links
using the corresponding mpsc sender. The forwarder also sends stateless packets to their hosts.

When a packet is read from the TLS tunnel, the forwarder identifies the packet and decides if and
how to handle it. The forwarder ONLY handles outbound traffic and does not send anything back to the client.

The forwarder creates and destroys links as needed, so that the server doesn't listen for a dead connection.

### Responder
The responder listens to incoming packets from the in-links using a multiple-sender-single-receiver system.
Upon receiving a packet, the responder simply sends it through the TLS tunnel back to the client

### Links
Each out-link is equipped with a mpsc receiver through which it receives packets included in its connection.
The out-link spoofs the packet and sends it through a raw socket which the kernel then handles.

The in-link is has the reversed task, listening to the socket for incoming packets, de-spoofing and sending
it to the responder. 

It should be noted that stateless packets do not spawn out-links because traffic is immediately forwarded,
although they do spawn short-lived in-links that self-destruct after sending the response-packet to the
responder.
