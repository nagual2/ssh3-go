use std::fmt;
use std::io::{self, Read};

pub const MIN_VARINT: u64 = 0;
pub const MAX_VARINT: u64 = MAX_VARINT_8;

const MAX_VARINT_1: u64 = 63;
const MAX_VARINT_2: u64 = 16_383;
const MAX_VARINT_4: u64 = 1_073_741_823;
const MAX_VARINT_8: u64 = 4_611_686_018_427_387_903;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidBool(u8),
    InvalidLength(u64),
    UnknownMessageType(u64),
    UnknownRequestType(Vec<u8>),
    InvalidForwardingProtocol(u64),
    InvalidAddressFamily(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::InvalidBool(value) => write!(f, "invalid SSH boolean byte: {value}"),
            Self::InvalidLength(length) => {
                write!(f, "SSH string length does not fit in memory: {length}")
            }
            Self::UnknownMessageType(kind) => write!(f, "unknown SSH message type: {kind}"),
            Self::UnknownRequestType(kind) => {
                write!(f, "unknown channel request type: {:?}", kind)
            }
            Self::InvalidForwardingProtocol(protocol) => {
                write!(f, "invalid forwarding protocol: {protocol}")
            }
            Self::InvalidAddressFamily(family) => write!(f, "invalid address family: {family}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn read_var_int<R: Read>(reader: &mut R) -> Result<u64> {
    let first_byte = read_byte(reader)?;
    let len = 1 << ((first_byte & 0xc0) >> 6);
    let b1 = first_byte & 0x3f;
    if len == 1 {
        return Ok(u64::from(b1));
    }

    let b2 = read_byte(reader)?;
    if len == 2 {
        return Ok(u64::from(b2) + (u64::from(b1) << 8));
    }

    let b3 = read_byte(reader)?;
    let b4 = read_byte(reader)?;
    if len == 4 {
        return Ok(u64::from(b4)
            + (u64::from(b3) << 8)
            + (u64::from(b2) << 16)
            + (u64::from(b1) << 24));
    }

    let b5 = read_byte(reader)?;
    let b6 = read_byte(reader)?;
    let b7 = read_byte(reader)?;
    let b8 = read_byte(reader)?;
    Ok(u64::from(b8)
        + (u64::from(b7) << 8)
        + (u64::from(b6) << 16)
        + (u64::from(b5) << 24)
        + (u64::from(b4) << 32)
        + (u64::from(b3) << 40)
        + (u64::from(b2) << 48)
        + (u64::from(b1) << 56))
}

pub fn append_var_int(out: &mut Vec<u8>, value: u64) {
    if value <= MAX_VARINT_1 {
        out.push(value as u8);
    } else if value <= MAX_VARINT_2 {
        out.extend_from_slice(&[((value >> 8) as u8) | 0x40, value as u8]);
    } else if value <= MAX_VARINT_4 {
        out.extend_from_slice(&[
            ((value >> 24) as u8) | 0x80,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]);
    } else if value <= MAX_VARINT_8 {
        out.extend_from_slice(&[
            ((value >> 56) as u8) | 0xc0,
            (value >> 48) as u8,
            (value >> 40) as u8,
            (value >> 32) as u8,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]);
    } else {
        panic!("{value:#x} doesn't fit into 62 bits");
    }
}

pub fn append_var_int_with_len(out: &mut Vec<u8>, value: u64, length: usize) {
    if !matches!(length, 1 | 2 | 4 | 8) {
        panic!("invalid varint length");
    }

    let actual_len = var_int_len(value);
    if actual_len > length {
        panic!("cannot encode {value} in {length} bytes");
    }
    if actual_len == length {
        append_var_int(out, value);
        return;
    }

    match length {
        2 => out.push(0b0100_0000),
        4 => out.push(0b1000_0000),
        8 => out.push(0b1100_0000),
        _ => {}
    }

    for _ in 1..(length - actual_len) {
        out.push(0);
    }

    for shift_index in (0..actual_len).rev() {
        out.push((value >> (shift_index * 8)) as u8);
    }
}

pub fn var_int_len(value: u64) -> usize {
    if value <= MAX_VARINT_1 {
        1
    } else if value <= MAX_VARINT_2 {
        2
    } else if value <= MAX_VARINT_4 {
        4
    } else if value <= MAX_VARINT_8 {
        8
    } else {
        panic!("value doesn't fit into 62 bits: {value}");
    }
}

pub fn read_ssh_bytes<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let length = read_var_int(reader)?;
    let length = usize::try_from(length).map_err(|_| Error::InvalidLength(length))?;
    let mut out = vec![0; length];
    reader.read_exact(&mut out)?;
    Ok(out)
}

pub fn append_ssh_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    append_var_int(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub fn ssh_string_len(bytes: &[u8]) -> usize {
    var_int_len(bytes.len() as u64) + bytes.len()
}

pub fn read_bool<R: Read>(reader: &mut R) -> Result<bool> {
    match read_byte(reader)? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(Error::InvalidBool(value)),
    }
}

pub fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

pub fn min_u64(a: u64, b: u64) -> u64 {
    if a <= b { a } else { b }
}

fn read_byte<R: Read>(reader: &mut R) -> Result<u8> {
    let mut byte = [0; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{
        MAX_VARINT, append_ssh_bytes, append_var_int, append_var_int_with_len, min_u64,
        read_ssh_bytes, read_var_int, ssh_string_len, var_int_len,
    };

    #[test]
    fn var_int_round_trips_at_boundaries() {
        let cases = [
            (0, vec![0x00]),
            (63, vec![0x3f]),
            (64, vec![0x40, 0x40]),
            (16_383, vec![0x7f, 0xff]),
            (16_384, vec![0x80, 0x00, 0x40, 0x00]),
            (1_073_741_823, vec![0xbf, 0xff, 0xff, 0xff]),
            (
                1_073_741_824,
                vec![0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00],
            ),
            (
                MAX_VARINT,
                vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        for (value, expected) in cases {
            let mut encoded = Vec::new();
            append_var_int(&mut encoded, value);
            assert_eq!(encoded, expected);
            assert_eq!(var_int_len(value), expected.len());

            let mut cursor = Cursor::new(encoded);
            let decoded = read_var_int(&mut cursor).unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn append_var_int_with_explicit_length_uses_requested_size() {
        let mut encoded = Vec::new();
        append_var_int_with_len(&mut encoded, 63, 2);
        assert_eq!(encoded, vec![0x40, 0x3f]);
    }

    #[test]
    fn ssh_bytes_round_trip() {
        let value = b"ssh3-bytes".to_vec();
        let mut encoded = Vec::new();
        append_ssh_bytes(&mut encoded, &value);
        assert_eq!(encoded.len(), ssh_string_len(&value));

        let mut cursor = Cursor::new(encoded);
        let decoded = read_ssh_bytes(&mut cursor).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn min_u64_returns_the_smaller_value() {
        assert_eq!(min_u64(4, 9), 4);
        assert_eq!(min_u64(9, 4), 4);
    }
}
