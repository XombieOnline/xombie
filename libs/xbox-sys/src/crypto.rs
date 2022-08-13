use bytes::BufMut;

use crate::codec::{BufPut, Decode, decode_array_u8};
use crate::std::fmt;

pub mod keys;

pub const SYMMETRIC_KEY_LEN: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymmetricKey(pub [u8;SYMMETRIC_KEY_LEN]);

impl SymmetricKey {
    pub fn parse_str(s: &str) -> Option<SymmetricKey> {
        let buf = parse_hex_buffer(s)?;
        Some(SymmetricKey(buf))
    }
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for SymmetricKey {
    fn put(&self, buf: &mut AnyBufMut) {
        buf.put_slice(&self.0)
    }
}

impl Decode for SymmetricKey {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, val) = decode_array_u8(input)?;
        Ok((input, SymmetricKey(val)))
    }
}

impl fmt::Display for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?
        }

        Ok(())
    }
}

fn parse_hex_buffer<const N: usize>(s: &str) -> Option<[u8;N]> {
    if s.len() != N * 2 {
        return None;
    }

    let mut buf = [0;N];
    for (i, bytes) in s.as_bytes().chunks(2).enumerate() {
        let hi = nybble_str(bytes[0])?;
        let lo = nybble_str(bytes[1])?;

        buf[i] = (hi << 4) | lo;
    }

    Some(buf)
}

fn nybble_str(c: u8) -> Option<u8> {
    Some(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 0xa,
        b'A'..=b'F' => c - b'A' + 0xA,
        _ => return None,
    })
}

pub const DES_IV_LEN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DesIv(pub [u8;DES_IV_LEN]);

impl Decode for DesIv {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, arr) = decode_array_u8(input)?;

        Ok((input, DesIv(arr)))        
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn parse_key_str() {
        assert_eq!(SymmetricKey::parse_str("f8d4863cac0eda58813b7a6d4a7eb4a3"),
            Some(SymmetricKey(hex!["f8d4863cac0eda58813b7a6d4a7eb4a3"])))
    }
}