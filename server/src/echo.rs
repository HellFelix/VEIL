use pnet::packet::{
    icmp::{
        self, echo_reply::MutableEchoReplyPacket, echo_request::EchoRequestPacket, IcmpPacket,
        IcmpTypes::EchoReply,
    },
    ipv4::{self, Ipv4Packet, MutableIpv4Packet},
    Packet,
};

pub fn create_echo_reply(incoming: &[u8]) -> Option<Vec<u8>> {
    let mut incoming = incoming.to_owned();

    #[cfg(target_os = "macos")]
    // Packets on the utun interface have a 4-byte header
    let mut ipv4_header = MutableIpv4Packet::new(&mut incoming[4..])?;

    #[cfg(target_os = "linux")]
    let mut ipv4_header = MutableIpv4Packet::new(&mut incoming[..])?;
    let icmp_request = EchoRequestPacket::new(ipv4_header.payload())?;

    let mut icmp_buffer = vec![0; ipv4_header.payload().len()];
    let mut icmp_reply = MutableEchoReplyPacket::new(&mut icmp_buffer)?;
    icmp_reply.set_icmp_type(EchoReply);
    icmp_reply.set_icmp_code(icmp::IcmpCode(0));
    icmp_reply.set_identifier(icmp_request.get_identifier());
    icmp_reply.set_sequence_number(icmp_request.get_sequence_number());
    icmp_reply.set_payload(icmp_request.payload());
    let icmp_packet = IcmpPacket::new(icmp_reply.packet())?;
    icmp_reply.set_checksum(icmp::checksum(&icmp_packet));

    let destination = ipv4_header.get_destination();
    ipv4_header.set_destination(ipv4_header.get_source());
    ipv4_header.set_source(destination);
    ipv4_header.set_payload(icmp_reply.packet());
    let ipv4_packet = Ipv4Packet::new(ipv4_header.packet())?;
    ipv4_header.set_checksum(ipv4::checksum(&ipv4_packet));

    incoming.into()
}
