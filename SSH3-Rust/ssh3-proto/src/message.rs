use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::wire::{
    Error, Result, append_ssh_bytes, append_var_int, read_bool, read_ssh_bytes, read_var_int,
    ssh_string_len, var_int_len, write_bool,
};

pub const SSH_MSG_DISCONNECT: u64 = 1;
pub const SSH_MSG_IGNORE: u64 = 2;
pub const SSH_MSG_UNIMPLEMENTED: u64 = 3;
pub const SSH_MSG_DEBUG: u64 = 4;
pub const SSH_MSG_SERVICE_REQUEST: u64 = 5;
pub const SSH_MSG_SERVICE_ACCEPT: u64 = 6;
pub const SSH_MSG_KEXINIT: u64 = 20;
pub const SSH_MSG_NEWKEYS: u64 = 21;
pub const SSH_MSG_USERAUTH_REQUEST: u64 = 50;
pub const SSH_MSG_USERAUTH_FAILURE: u64 = 51;
pub const SSH_MSG_USERAUTH_SUCCESS: u64 = 52;
pub const SSH_MSG_USERAUTH_BANNER: u64 = 53;
pub const SSH_MSG_GLOBAL_REQUEST: u64 = 80;
pub const SSH_MSG_REQUEST_SUCCESS: u64 = 81;
pub const SSH_MSG_REQUEST_FAILURE: u64 = 82;
pub const SSH_MSG_CHANNEL_OPEN: u64 = 90;
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u64 = 91;
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u64 = 92;
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u64 = 93;
pub const SSH_MSG_CHANNEL_DATA: u64 = 94;
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u64 = 95;
pub const SSH_MSG_CHANNEL_EOF: u64 = 96;
pub const SSH_MSG_CHANNEL_CLOSE: u64 = 97;
pub const SSH_MSG_CHANNEL_REQUEST: u64 = 98;
pub const SSH_MSG_CHANNEL_SUCCESS: u64 = 99;
pub const SSH_MSG_CHANNEL_FAILURE: u64 = 100;

pub type SshDataType = u64;

pub const SSH_EXTENDED_DATA_NONE: SshDataType = 0;
pub const SSH_EXTENDED_DATA_STDERR: SshDataType = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    ChannelRequest(ChannelRequestMessage),
    ChannelOpenConfirmation(ChannelOpenConfirmationMessage),
    ChannelOpenFailure(ChannelOpenFailureMessage),
    Data(DataOrExtendedDataMessage),
}

impl Message {
    pub fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        match read_var_int(reader)? {
            SSH_MSG_CHANNEL_REQUEST => Ok(Self::ChannelRequest(
                ChannelRequestMessage::parse_payload(reader)?,
            )),
            SSH_MSG_CHANNEL_OPEN_CONFIRMATION => Ok(Self::ChannelOpenConfirmation(
                ChannelOpenConfirmationMessage::parse_payload(reader)?,
            )),
            SSH_MSG_CHANNEL_OPEN_FAILURE => Ok(Self::ChannelOpenFailure(
                ChannelOpenFailureMessage::parse_payload(reader)?,
            )),
            SSH_MSG_CHANNEL_DATA => Ok(Self::Data(DataOrExtendedDataMessage::parse_data_payload(
                reader,
            )?)),
            SSH_MSG_CHANNEL_EXTENDED_DATA => Ok(Self::Data(
                DataOrExtendedDataMessage::parse_extended_payload(reader)?,
            )),
            kind => Err(Error::UnknownMessageType(kind)),
        }
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            Self::ChannelRequest(message) => message.encoded_len(),
            Self::ChannelOpenConfirmation(message) => message.encoded_len(),
            Self::ChannelOpenFailure(message) => message.encoded_len(),
            Self::Data(message) => message.encoded_len(),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::ChannelRequest(message) => message.encode(out),
            Self::ChannelOpenConfirmation(message) => message.encode(out),
            Self::ChannelOpenFailure(message) => message.encode(out),
            Self::Data(message) => message.encode(out),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelOpenConfirmationMessage {
    pub max_packet_size: u64,
}

impl ChannelOpenConfirmationMessage {
    fn parse_payload<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            max_packet_size: read_var_int(reader)?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        var_int_len(SSH_MSG_CHANNEL_OPEN_CONFIRMATION) + var_int_len(self.max_packet_size)
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        append_var_int(out, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        append_var_int(out, self.max_packet_size);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelOpenFailureMessage {
    pub reason_code: u64,
    pub error_message_utf8: Vec<u8>,
    pub language_tag: Vec<u8>,
}

impl ChannelOpenFailureMessage {
    fn parse_payload<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            reason_code: read_var_int(reader)?,
            error_message_utf8: read_ssh_bytes(reader)?,
            language_tag: read_ssh_bytes(reader)?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        var_int_len(SSH_MSG_CHANNEL_OPEN_FAILURE)
            + var_int_len(self.reason_code)
            + ssh_string_len(&self.error_message_utf8)
            + ssh_string_len(&self.language_tag)
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        append_var_int(out, SSH_MSG_CHANNEL_OPEN_FAILURE);
        append_var_int(out, self.reason_code);
        append_ssh_bytes(out, &self.error_message_utf8);
        append_ssh_bytes(out, &self.language_tag);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataOrExtendedDataMessage {
    pub data_type: SshDataType,
    pub data: Vec<u8>,
}

impl DataOrExtendedDataMessage {
    fn parse_data_payload<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            data_type: SSH_EXTENDED_DATA_NONE,
            data: read_ssh_bytes(reader)?,
        })
    }

    fn parse_extended_payload<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            data_type: read_var_int(reader)?,
            data: read_ssh_bytes(reader)?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        if self.data_type == SSH_EXTENDED_DATA_NONE {
            var_int_len(SSH_MSG_CHANNEL_DATA) + ssh_string_len(&self.data)
        } else {
            var_int_len(SSH_MSG_CHANNEL_EXTENDED_DATA)
                + var_int_len(self.data_type)
                + ssh_string_len(&self.data)
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        if self.data_type == SSH_EXTENDED_DATA_NONE {
            append_var_int(out, SSH_MSG_CHANNEL_DATA);
        } else {
            append_var_int(out, SSH_MSG_CHANNEL_EXTENDED_DATA);
            append_var_int(out, self.data_type);
        }
        append_ssh_bytes(out, &self.data);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelRequestMessage {
    pub want_reply: bool,
    pub request: ChannelRequest,
}

impl ChannelRequestMessage {
    fn parse_payload<R: Read>(reader: &mut R) -> Result<Self> {
        let request_type = read_ssh_bytes(reader)?;
        let want_reply = read_bool(reader)?;
        let request = ChannelRequest::parse(&request_type, reader)?;
        Ok(Self {
            want_reply,
            request,
        })
    }

    pub fn encoded_len(&self) -> usize {
        var_int_len(SSH_MSG_CHANNEL_REQUEST)
            + ssh_string_len(self.request.request_type())
            + 1
            + self.request.encoded_payload_len()
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        append_var_int(out, SSH_MSG_CHANNEL_REQUEST);
        append_ssh_bytes(out, self.request.request_type());
        write_bool(out, self.want_reply);
        self.request.encode_payload(out);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelRequest {
    Pty(PtyRequest),
    X11(X11Request),
    Shell,
    Exec(ExecRequest),
    Subsystem(SubsystemRequest),
    WindowChange(WindowChangeRequest),
    Signal(SignalRequest),
    ExitStatus(ExitStatusRequest),
    ExitSignal(ExitSignalRequest),
    ForwardPort(ForwardingRequest),
}

impl ChannelRequest {
    fn parse<R: Read>(request_type: &[u8], reader: &mut R) -> Result<Self> {
        match request_type {
            b"pty-req" => Ok(Self::Pty(PtyRequest::parse(reader)?)),
            b"x11-req" => Ok(Self::X11(X11Request::parse(reader)?)),
            b"shell" => Ok(Self::Shell),
            b"exec" => Ok(Self::Exec(ExecRequest::parse(reader)?)),
            b"subsystem" => Ok(Self::Subsystem(SubsystemRequest::parse(reader)?)),
            b"window-change" => Ok(Self::WindowChange(WindowChangeRequest::parse(reader)?)),
            b"signal" => Ok(Self::Signal(SignalRequest::parse(reader)?)),
            b"exit-status" => Ok(Self::ExitStatus(ExitStatusRequest::parse(reader)?)),
            b"exit-signal" => Ok(Self::ExitSignal(ExitSignalRequest::parse(reader)?)),
            b"forward-port" => Ok(Self::ForwardPort(ForwardingRequest::parse(reader)?)),
            _ => Err(Error::UnknownRequestType(request_type.to_vec())),
        }
    }

    fn request_type(&self) -> &'static [u8] {
        match self {
            Self::Pty(_) => b"pty-req",
            Self::X11(_) => b"x11-req",
            Self::Shell => b"shell",
            Self::Exec(_) => b"exec",
            Self::Subsystem(_) => b"subsystem",
            Self::WindowChange(_) => b"window-change",
            Self::Signal(_) => b"signal",
            Self::ExitStatus(_) => b"exit-status",
            Self::ExitSignal(_) => b"exit-signal",
            Self::ForwardPort(_) => b"forward-port",
        }
    }

    fn encoded_payload_len(&self) -> usize {
        match self {
            Self::Pty(request) => request.encoded_len(),
            Self::X11(request) => request.encoded_len(),
            Self::Shell => 0,
            Self::Exec(request) => request.encoded_len(),
            Self::Subsystem(request) => request.encoded_len(),
            Self::WindowChange(request) => request.encoded_len(),
            Self::Signal(request) => request.encoded_len(),
            Self::ExitStatus(request) => request.encoded_len(),
            Self::ExitSignal(request) => request.encoded_len(),
            Self::ForwardPort(request) => request.encoded_len(),
        }
    }

    fn encode_payload(&self, out: &mut Vec<u8>) {
        match self {
            Self::Pty(request) => request.encode(out),
            Self::X11(request) => request.encode(out),
            Self::Shell => {}
            Self::Exec(request) => request.encode(out),
            Self::Subsystem(request) => request.encode(out),
            Self::WindowChange(request) => request.encode(out),
            Self::Signal(request) => request.encode(out),
            Self::ExitStatus(request) => request.encode(out),
            Self::ExitSignal(request) => request.encode(out),
            Self::ForwardPort(request) => request.encode(out),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PtyRequest {
    pub term: Vec<u8>,
    pub char_width: u64,
    pub char_height: u64,
    pub pixel_width: u64,
    pub pixel_height: u64,
    pub encoded_terminal_modes: Vec<u8>,
}

impl PtyRequest {
    fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            term: read_ssh_bytes(reader)?,
            char_width: read_var_int(reader)?,
            char_height: read_var_int(reader)?,
            pixel_width: read_var_int(reader)?,
            pixel_height: read_var_int(reader)?,
            encoded_terminal_modes: read_ssh_bytes(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        ssh_string_len(&self.term)
            + var_int_len(self.char_width)
            + var_int_len(self.char_height)
            + var_int_len(self.pixel_width)
            + var_int_len(self.pixel_height)
            + ssh_string_len(&self.encoded_terminal_modes)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_ssh_bytes(out, &self.term);
        append_var_int(out, self.char_width);
        append_var_int(out, self.char_height);
        append_var_int(out, self.pixel_width);
        append_var_int(out, self.pixel_height);
        append_ssh_bytes(out, &self.encoded_terminal_modes);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X11Request {
    pub single_connection: bool,
    pub x11_authentication_protocol: Vec<u8>,
    pub x11_authentication_cookie: Vec<u8>,
    pub x11_screen_number: u64,
}

impl X11Request {
    fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            single_connection: read_bool(reader)?,
            x11_authentication_protocol: read_ssh_bytes(reader)?,
            x11_authentication_cookie: read_ssh_bytes(reader)?,
            x11_screen_number: read_var_int(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        1 + ssh_string_len(&self.x11_authentication_protocol)
            + ssh_string_len(&self.x11_authentication_cookie)
            + var_int_len(self.x11_screen_number)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        write_bool(out, self.single_connection);
        append_ssh_bytes(out, &self.x11_authentication_protocol);
        append_ssh_bytes(out, &self.x11_authentication_cookie);
        append_var_int(out, self.x11_screen_number);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecRequest {
    pub command: Vec<u8>,
}

impl ExecRequest {
    fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            command: read_ssh_bytes(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        ssh_string_len(&self.command)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_ssh_bytes(out, &self.command);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubsystemRequest {
    pub subsystem_name: Vec<u8>,
}

impl SubsystemRequest {
    fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            subsystem_name: read_ssh_bytes(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        ssh_string_len(&self.subsystem_name)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_ssh_bytes(out, &self.subsystem_name);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowChangeRequest {
    pub char_width: u64,
    pub char_height: u64,
    pub pixel_width: u64,
    pub pixel_height: u64,
}

impl WindowChangeRequest {
    fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            char_width: read_var_int(reader)?,
            char_height: read_var_int(reader)?,
            pixel_width: read_var_int(reader)?,
            pixel_height: read_var_int(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        var_int_len(self.char_width)
            + var_int_len(self.char_height)
            + var_int_len(self.pixel_width)
            + var_int_len(self.pixel_height)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_var_int(out, self.char_width);
        append_var_int(out, self.char_height);
        append_var_int(out, self.pixel_width);
        append_var_int(out, self.pixel_height);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalRequest {
    pub signal_name_without_sig: Vec<u8>,
}

impl SignalRequest {
    fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            signal_name_without_sig: read_ssh_bytes(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        ssh_string_len(&self.signal_name_without_sig)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_ssh_bytes(out, &self.signal_name_without_sig);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitStatusRequest {
    pub exit_status: u64,
}

impl ExitStatusRequest {
    fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            exit_status: read_var_int(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        var_int_len(self.exit_status)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_var_int(out, self.exit_status);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitSignalRequest {
    pub signal_name_without_sig: Vec<u8>,
    pub core_dumped: bool,
    pub error_message_utf8: Vec<u8>,
    pub language_tag: Vec<u8>,
}

impl ExitSignalRequest {
    fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            signal_name_without_sig: read_ssh_bytes(reader)?,
            core_dumped: read_bool(reader)?,
            error_message_utf8: read_ssh_bytes(reader)?,
            language_tag: read_ssh_bytes(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        ssh_string_len(&self.signal_name_without_sig)
            + 1
            + ssh_string_len(&self.error_message_utf8)
            + ssh_string_len(&self.language_tag)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_ssh_bytes(out, &self.signal_name_without_sig);
        write_bool(out, self.core_dumped);
        append_ssh_bytes(out, &self.error_message_utf8);
        append_ssh_bytes(out, &self.language_tag);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum ForwardingProtocol {
    Udp = 0,
    Tcp = 1,
}

impl ForwardingProtocol {
    pub(crate) fn as_u64(self) -> u64 {
        self as u64
    }
}

impl TryFrom<u64> for ForwardingProtocol {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Udp),
            1 => Ok(Self::Tcp),
            _ => Err(Error::InvalidForwardingProtocol(value)),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum ForwardingAddressFamily {
    Ipv4 = 4,
    Ipv6 = 6,
}

impl ForwardingAddressFamily {
    pub(crate) fn octet_len(self) -> usize {
        match self {
            Self::Ipv4 => 4,
            Self::Ipv6 => 16,
        }
    }

    pub(crate) fn as_u64(self) -> u64 {
        self as u64
    }

    pub(crate) fn from_ip(ip_address: IpAddr) -> Self {
        match ip_address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

impl TryFrom<u64> for ForwardingAddressFamily {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self> {
        match value {
            4 => Ok(Self::Ipv4),
            6 => Ok(Self::Ipv6),
            _ => Err(Error::InvalidAddressFamily(value)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardingRequest {
    pub protocol: ForwardingProtocol,
    pub ip_address: IpAddr,
    pub port: u16,
}

impl ForwardingRequest {
    fn parse<R: Read>(reader: &mut R) -> Result<Self> {
        let protocol = ForwardingProtocol::try_from(read_var_int(reader)?)?;
        let family = ForwardingAddressFamily::try_from(read_var_int(reader)?)?;
        let mut octets = vec![0; family.octet_len()];
        reader.read_exact(&mut octets)?;
        let ip_address = match family {
            ForwardingAddressFamily::Ipv4 => {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap()))
            }
            ForwardingAddressFamily::Ipv6 => {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap()))
            }
        };

        let mut port = [0; 2];
        reader.read_exact(&mut port)?;
        Ok(Self {
            protocol,
            ip_address,
            port: u16::from_be_bytes(port),
        })
    }

    fn encoded_len(&self) -> usize {
        let family = ForwardingAddressFamily::from_ip(self.ip_address);
        var_int_len(self.protocol.as_u64()) + var_int_len(family.as_u64()) + family.octet_len() + 2
    }

    fn encode(&self, out: &mut Vec<u8>) {
        let family = ForwardingAddressFamily::from_ip(self.ip_address);
        append_var_int(out, self.protocol.as_u64());
        append_var_int(out, family.as_u64());
        match self.ip_address {
            IpAddr::V4(address) => out.extend_from_slice(&address.octets()),
            IpAddr::V6(address) => out.extend_from_slice(&address.octets()),
        }
        out.extend_from_slice(&self.port.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        ChannelOpenConfirmationMessage, ChannelOpenFailureMessage, ChannelRequest,
        ChannelRequestMessage, DataOrExtendedDataMessage, ExecRequest, ExitSignalRequest,
        ExitStatusRequest, ForwardingProtocol, ForwardingRequest, Message, PtyRequest,
        SSH_EXTENDED_DATA_NONE, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA,
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_REQUEST,
        SignalRequest, SubsystemRequest, WindowChangeRequest, X11Request,
    };
    use crate::wire::{append_ssh_bytes, append_var_int, write_bool};

    const EXTENDED_DATA_TYPE: u64 = 10_000_000;

    fn patterned_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn parse_message(bytes: &[u8]) -> Message {
        Message::parse(&mut Cursor::new(bytes)).unwrap()
    }

    fn encode_request_bytes(request_type: &[u8], want_reply: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        append_var_int(&mut out, SSH_MSG_CHANNEL_REQUEST);
        append_ssh_bytes(&mut out, request_type);
        write_bool(&mut out, want_reply);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parses_and_writes_data_messages() {
        let large_data = patterned_bytes(128 * 1024);
        let cases = [
            Vec::from(b"hello, world!".as_slice()),
            Vec::new(),
            large_data,
        ];

        for data in cases {
            let message = Message::Data(DataOrExtendedDataMessage {
                data_type: SSH_EXTENDED_DATA_NONE,
                data: data.clone(),
            });
            let mut expected = Vec::new();
            append_var_int(&mut expected, SSH_MSG_CHANNEL_DATA);
            append_ssh_bytes(&mut expected, &data);

            assert_eq!(message.encoded_len(), expected.len());
            assert_eq!(message.to_vec(), expected);
            assert_eq!(parse_message(&expected), message);
        }
    }

    #[test]
    fn parses_and_writes_extended_data_messages() {
        let large_data = patterned_bytes(128 * 1024);
        let cases = [
            Vec::from(b"hello, world!".as_slice()),
            Vec::new(),
            large_data,
        ];

        for data in cases {
            let message = Message::Data(DataOrExtendedDataMessage {
                data_type: EXTENDED_DATA_TYPE,
                data: data.clone(),
            });
            let mut expected = Vec::new();
            append_var_int(&mut expected, SSH_MSG_CHANNEL_EXTENDED_DATA);
            append_var_int(&mut expected, EXTENDED_DATA_TYPE);
            append_ssh_bytes(&mut expected, &data);

            assert_eq!(message.encoded_len(), expected.len());
            assert_eq!(message.to_vec(), expected);
            assert_eq!(parse_message(&expected), message);
        }
    }

    #[test]
    fn parses_and_writes_channel_request_messages() {
        let large_bytes = patterned_bytes(1024);
        let term = large_bytes[..100].to_vec();
        let encoded_modes = large_bytes[100..600].to_vec();
        let x11_protocol = large_bytes[..100].to_vec();
        let x11_cookie = large_bytes[100..500].to_vec();
        let exec_command = large_bytes.clone();
        let subsystem_name = large_bytes.clone();
        let signal_name = large_bytes.clone();
        let exit_signal_name = large_bytes[..100].to_vec();
        let error_message = large_bytes[100..500].to_vec();
        let language_tag = large_bytes[500..700].to_vec();

        let pty_payload = {
            let mut payload = Vec::new();
            append_ssh_bytes(&mut payload, &term);
            append_var_int(&mut payload, 9_001);
            append_var_int(&mut payload, 9_002);
            append_var_int(&mut payload, 9_003);
            append_var_int(&mut payload, 9_004);
            append_ssh_bytes(&mut payload, &encoded_modes);
            payload
        };
        let pty_message = Message::ChannelRequest(ChannelRequestMessage {
            want_reply: true,
            request: ChannelRequest::Pty(PtyRequest {
                term,
                char_width: 9_001,
                char_height: 9_002,
                pixel_width: 9_003,
                pixel_height: 9_004,
                encoded_terminal_modes: encoded_modes,
            }),
        });
        let pty_bytes = encode_request_bytes(b"pty-req", true, &pty_payload);

        let x11_payload = {
            let mut payload = Vec::new();
            write_bool(&mut payload, false);
            append_ssh_bytes(&mut payload, &x11_protocol);
            append_ssh_bytes(&mut payload, &x11_cookie);
            append_var_int(&mut payload, 4_096);
            payload
        };
        let x11_message = Message::ChannelRequest(ChannelRequestMessage {
            want_reply: false,
            request: ChannelRequest::X11(X11Request {
                single_connection: false,
                x11_authentication_protocol: x11_protocol,
                x11_authentication_cookie: x11_cookie,
                x11_screen_number: 4_096,
            }),
        });
        let x11_bytes = encode_request_bytes(b"x11-req", false, &x11_payload);

        let shell_message = Message::ChannelRequest(ChannelRequestMessage {
            want_reply: true,
            request: ChannelRequest::Shell,
        });
        let shell_bytes = encode_request_bytes(b"shell", true, &[]);

        let exec_payload = {
            let mut payload = Vec::new();
            append_ssh_bytes(&mut payload, &exec_command);
            payload
        };
        let exec_message = Message::ChannelRequest(ChannelRequestMessage {
            want_reply: false,
            request: ChannelRequest::Exec(ExecRequest {
                command: exec_command,
            }),
        });
        let exec_bytes = encode_request_bytes(b"exec", false, &exec_payload);

        let subsystem_payload = {
            let mut payload = Vec::new();
            append_ssh_bytes(&mut payload, &subsystem_name);
            payload
        };
        let subsystem_message = Message::ChannelRequest(ChannelRequestMessage {
            want_reply: true,
            request: ChannelRequest::Subsystem(SubsystemRequest { subsystem_name }),
        });
        let subsystem_bytes = encode_request_bytes(b"subsystem", true, &subsystem_payload);

        let window_change_payload = {
            let mut payload = Vec::new();
            append_var_int(&mut payload, 80);
            append_var_int(&mut payload, 24);
            append_var_int(&mut payload, 1_280);
            append_var_int(&mut payload, 720);
            payload
        };
        let window_change_message = Message::ChannelRequest(ChannelRequestMessage {
            want_reply: false,
            request: ChannelRequest::WindowChange(WindowChangeRequest {
                char_width: 80,
                char_height: 24,
                pixel_width: 1_280,
                pixel_height: 720,
            }),
        });
        let window_change_bytes =
            encode_request_bytes(b"window-change", false, &window_change_payload);

        let signal_payload = {
            let mut payload = Vec::new();
            append_ssh_bytes(&mut payload, &signal_name);
            payload
        };
        let signal_message = Message::ChannelRequest(ChannelRequestMessage {
            want_reply: true,
            request: ChannelRequest::Signal(SignalRequest {
                signal_name_without_sig: signal_name,
            }),
        });
        let signal_bytes = encode_request_bytes(b"signal", true, &signal_payload);

        let exit_status_payload = {
            let mut payload = Vec::new();
            append_var_int(&mut payload, 255);
            payload
        };
        let exit_status_message = Message::ChannelRequest(ChannelRequestMessage {
            want_reply: false,
            request: ChannelRequest::ExitStatus(ExitStatusRequest { exit_status: 255 }),
        });
        let exit_status_bytes = encode_request_bytes(b"exit-status", false, &exit_status_payload);

        let exit_signal_payload = {
            let mut payload = Vec::new();
            append_ssh_bytes(&mut payload, &exit_signal_name);
            write_bool(&mut payload, true);
            append_ssh_bytes(&mut payload, &error_message);
            append_ssh_bytes(&mut payload, &language_tag);
            payload
        };
        let exit_signal_message = Message::ChannelRequest(ChannelRequestMessage {
            want_reply: true,
            request: ChannelRequest::ExitSignal(ExitSignalRequest {
                signal_name_without_sig: exit_signal_name,
                core_dumped: true,
                error_message_utf8: error_message,
                language_tag,
            }),
        });
        let exit_signal_bytes = encode_request_bytes(b"exit-signal", true, &exit_signal_payload);

        let forwarding_payload = {
            let mut payload = Vec::new();
            append_var_int(&mut payload, ForwardingProtocol::Tcp as u64);
            append_var_int(&mut payload, 4);
            payload.extend_from_slice(&[192, 0, 2, 10]);
            payload.extend_from_slice(&443u16.to_be_bytes());
            payload
        };
        let forwarding_message = Message::ChannelRequest(ChannelRequestMessage {
            want_reply: false,
            request: ChannelRequest::ForwardPort(ForwardingRequest {
                protocol: ForwardingProtocol::Tcp,
                ip_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                port: 443,
            }),
        });
        let forwarding_bytes = encode_request_bytes(b"forward-port", false, &forwarding_payload);

        let cases = [
            (pty_message, pty_bytes),
            (x11_message, x11_bytes),
            (shell_message, shell_bytes),
            (exec_message, exec_bytes),
            (subsystem_message, subsystem_bytes),
            (window_change_message, window_change_bytes),
            (signal_message, signal_bytes),
            (exit_status_message, exit_status_bytes),
            (exit_signal_message, exit_signal_bytes),
            (forwarding_message, forwarding_bytes),
        ];

        for (message, expected_bytes) in cases {
            assert_eq!(message.encoded_len(), expected_bytes.len());
            assert_eq!(message.to_vec(), expected_bytes);
            assert_eq!(parse_message(&expected_bytes), message);
        }
    }

    #[test]
    fn parses_and_writes_channel_open_confirmation_messages() {
        let message = Message::ChannelOpenConfirmation(ChannelOpenConfirmationMessage {
            max_packet_size: 32_768,
        });
        let mut expected = Vec::new();
        append_var_int(&mut expected, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        append_var_int(&mut expected, 32_768);

        assert_eq!(message.encoded_len(), expected.len());
        assert_eq!(message.to_vec(), expected);
        assert_eq!(parse_message(&expected), message);
    }

    #[test]
    fn parses_and_writes_channel_open_failure_messages() {
        let error_message = patterned_bytes(100);
        let language_tag = patterned_bytes(32);
        let message = Message::ChannelOpenFailure(ChannelOpenFailureMessage {
            reason_code: 4_096,
            error_message_utf8: error_message.clone(),
            language_tag: language_tag.clone(),
        });
        let mut expected = Vec::new();
        append_var_int(&mut expected, SSH_MSG_CHANNEL_OPEN_FAILURE);
        append_var_int(&mut expected, 4_096);
        append_ssh_bytes(&mut expected, &error_message);
        append_ssh_bytes(&mut expected, &language_tag);

        assert_eq!(message.encoded_len(), expected.len());
        assert_eq!(message.to_vec(), expected);
        assert_eq!(parse_message(&expected), message);
    }
}
