use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::ForwardingAddressFamily;
use crate::wire::{Result, append_ssh_bytes, append_var_int, read_ssh_bytes, read_var_int};

pub const SSH_FRAME_TYPE: u64 = 0xaf36_27e6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelHeader {
    pub conversation_stream_id: u64,
    pub channel_type: Vec<u8>,
    pub max_packet_size: u64,
}

impl ChannelHeader {
    pub fn encode(&self, additional_bytes: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        append_var_int(&mut out, SSH_FRAME_TYPE);
        append_var_int(&mut out, self.conversation_stream_id);
        append_ssh_bytes(&mut out, &self.channel_type);
        append_var_int(&mut out, self.max_packet_size);
        if let Some(additional_bytes) = additional_bytes {
            out.extend_from_slice(additional_bytes);
        }
        out
    }

    pub fn parse_payload<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            conversation_stream_id: read_var_int(reader)?,
            channel_type: read_ssh_bytes(reader)?,
            max_packet_size: read_var_int(reader)?,
        })
    }
}

pub fn build_forwarding_additional_bytes(remote_addr: IpAddr, port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    let family = ForwardingAddressFamily::from_ip(remote_addr);
    append_var_int(&mut out, family as u64);
    match remote_addr {
        IpAddr::V4(address) => out.extend_from_slice(&address.octets()),
        IpAddr::V6(address) => out.extend_from_slice(&address.octets()),
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

pub fn parse_forwarding_payload<R: Read>(reader: &mut R) -> Result<SocketAddr> {
    let family = ForwardingAddressFamily::try_from(read_var_int(reader)?)?;
    let mut octets = vec![0; family.octet_len()];
    reader.read_exact(&mut octets)?;

    let mut port = [0; 2];
    reader.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);

    match family {
        ForwardingAddressFamily::Ipv4 => {
            let ip = Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap());
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        ForwardingAddressFamily::Ipv6 => {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap());
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
    }
}

pub fn parse_udp_forwarding_payload<R: Read>(reader: &mut R) -> Result<SocketAddr> {
    parse_forwarding_payload(reader)
}

pub fn parse_tcp_forwarding_payload<R: Read>(reader: &mut R) -> Result<SocketAddr> {
    parse_forwarding_payload(reader)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    use super::{
        ChannelHeader, SSH_FRAME_TYPE, build_forwarding_additional_bytes, parse_forwarding_payload,
        parse_tcp_forwarding_payload, parse_udp_forwarding_payload,
    };
    use crate::wire::{append_var_int, read_var_int};

    #[test]
    fn encodes_and_parses_channel_headers() {
        let header = ChannelHeader {
            conversation_stream_id: 42,
            channel_type: b"session".to_vec(),
            max_packet_size: 32_768,
        };
        let extra = vec![1, 2, 3, 4];
        let encoded = header.encode(Some(&extra));

        let mut cursor = Cursor::new(encoded);
        let frame_type = read_var_int(&mut cursor).unwrap();
        assert_eq!(frame_type, SSH_FRAME_TYPE);
        let parsed = ChannelHeader::parse_payload(&mut cursor).unwrap();
        assert_eq!(parsed, header);

        let mut remaining = Vec::new();
        cursor.read_to_end(&mut remaining).unwrap();
        assert_eq!(remaining, extra);
    }

    #[test]
    fn encodes_and_parses_ipv4_forwarding_payloads() {
        let payload =
            build_forwarding_additional_bytes(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 15)), 443);
        let expected = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 15), 443));

        assert_eq!(
            parse_forwarding_payload(&mut Cursor::new(payload.clone())).unwrap(),
            expected
        );
        assert_eq!(
            parse_udp_forwarding_payload(&mut Cursor::new(payload.clone())).unwrap(),
            expected
        );
        assert_eq!(
            parse_tcp_forwarding_payload(&mut Cursor::new(payload)).unwrap(),
            expected
        );
    }

    #[test]
    fn encodes_and_parses_ipv6_forwarding_payloads() {
        let payload = build_forwarding_additional_bytes(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1)),
            8443,
        );
        let expected = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1),
            8443,
            0,
            0,
        ));

        assert_eq!(
            parse_forwarding_payload(&mut Cursor::new(payload)).unwrap(),
            expected
        );
    }

    #[test]
    fn frame_type_matches_the_go_constant() {
        let mut encoded = Vec::new();
        append_var_int(&mut encoded, SSH_FRAME_TYPE);
        assert_eq!(
            encoded,
            vec![0xc0, 0x00, 0x00, 0x00, 0xaf, 0x36, 0x27, 0xe6]
        );
    }
}
