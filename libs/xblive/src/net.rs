use bytes::BufMut;

use std::net::Ipv4Addr;
use std::fmt;

use xbox_sys::codec::{BufPut, Decode, decode_array_u8};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct InAddr(pub [u8;4]);

impl InAddr {
    pub fn build(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for InAddr {
	fn put(&self, buf: &mut AnyBufMut) {
		buf.put_slice(&self.0)
	}
}

impl Decode for InAddr {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, val) = decode_array_u8(input)?;
        Ok((input, InAddr(val)))
    }
}

impl From<&Ipv4Addr> for InAddr {
    fn from(other: &Ipv4Addr) -> Self {
        Self(other.octets())
    }
}

pub const ETH_ADDR_LEN: usize = 6;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Eui48(pub [u8;ETH_ADDR_LEN]);

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for Eui48 {
	fn put(&self, buf: &mut AnyBufMut) {
		buf.put_slice(&self.0)
	}
}

impl Decode for Eui48 {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, val) = decode_array_u8(input)?;

        Ok((input, Eui48(val)))
    }
}

impl fmt::Display for Eui48 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2],
            self.0[3], self.0[4], self.0[5])
    }
}

impl fmt::Debug for Eui48 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <self::Eui48 as fmt::Display>::fmt(&self, f)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use xbox_sys::codec::test_codec;

    use super::*;

    #[test]
    fn inaddr_codec() {
        test_codec(
            &hex!["abcdef45"],
            InAddr([0xab, 0xcd, 0xef, 0x45]),
        )
    }

    #[test]
    fn eui48_display() {
        assert_eq!("54:84:78:ab:01:99",
            format!("{}", Eui48(hex!["54 84 78 ab 01 99"])))
    }

    #[test]
    fn eui48_codec() {
        test_codec(
            &hex!["54 84 78 ab 01 99"],
            Eui48(hex!["54 84 78 ab 01 99"]),
        );
    }
}