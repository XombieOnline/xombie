use bytes::BufMut;

use nom::number::complete::le_u32;

use xbox_sys::account::Xuid;
use xbox_sys::codec::{BufPut, Decode, decode_array_u8};

use crate::net::InAddr;

pub mod control;
pub mod packet;
pub mod seq;
pub mod tcp;
pub mod udp;

pub const UDP_PORT: u16 = 3074;

pub const SECURITY_PARAMETERS_INDEX_LEN: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SecurityParametersIndex(pub [u8;SECURITY_PARAMETERS_INDEX_LEN]);

impl SecurityParametersIndex {
    pub const EMPTY: SecurityParametersIndex = SecurityParametersIndex([0;SECURITY_PARAMETERS_INDEX_LEN]);
}

impl From<u32> for SecurityParametersIndex {
    fn from(val: u32) -> Self {
        let bytes = val.to_le_bytes();
        SecurityParametersIndex([bytes[1], bytes[2], bytes[3]])
    }
}

impl Into<u32> for SecurityParametersIndex {
    fn into(self) -> u32 {
        u32::from_le_bytes([0, self.0[0], self.0[1], self.0[2]])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SgAddr {
    pub ina_sg: InAddr,
    pub spi_sg: u32,
    pub xbox_id: Xuid,
    pub _rsvd_10: [u8;4],
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for SgAddr {
	fn put(&self, buf: &mut AnyBufMut) {
		self.ina_sg.put(buf);
        buf.put_u32_le(self.spi_sg);
        self.xbox_id.put(buf);
        buf.put_slice(&self._rsvd_10);
    }
}

impl Decode for SgAddr {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, ina_sg) = InAddr::decode(input)?;
        let (input, spi_sg) = le_u32(input)?;
        let (input, xbox_id) = Xuid::decode(input)?;
        let (input, _rsvd_10) = decode_array_u8(input)?;

        Ok((input, SgAddr {
            ina_sg,
            spi_sg,
            xbox_id,
            _rsvd_10,
        }))
    }
}

impl SgAddr {
    fn build(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.append(&mut self.ina_sg.build());
        buf.put_u32_le(self.spi_sg);
        buf.append(&mut self.xbox_id.build());
        buf.append(&mut self._rsvd_10.to_vec());

        buf
    }
}

pub const SG_NONCE_LEN: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SgNonce(pub [u8;SG_NONCE_LEN]);

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for SgNonce {
    fn put(&self, buf: &mut AnyBufMut) {
        buf.put_slice(&self.0)
    }
}

impl Decode for SgNonce {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, val) = decode_array_u8(input)?;
        Ok((input, SgNonce(val)))
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::*;

    use xbox_sys::codec::test_codec;

    use super::*;

    #[test]
    fn sgaddr_build() {
        let sgaddr = SgAddr {
            ina_sg: InAddr([10, 23, 45, 99]),
            spi_sg: 0x98765432,
            xbox_id: Xuid(0x0123456789abcdef),
            _rsvd_10: hex!["11223344"],
        };

        let expected = hex!["
            0A 17 2D 63
            32 54 76 98
            EF CD AB 89 67 45 23 01
            11 22 33 44
        "];

        let bytes = sgaddr.build();

        assert_eq!(bytes.len(), 0x14);

        assert_eq!(bytes, expected);
    }

    #[test]
    fn sgaddr_codec() {
        test_codec(
            &hex!["
                0A 17 2D 63
                32 54 76 98
                EF CD AB 89 67 45 23 01
                11 22 33 44"],
            SgAddr {
                ina_sg: InAddr([10, 23, 45, 99]),
                spi_sg: 0x98765432,
                xbox_id: Xuid(0x0123456789abcdef),
                _rsvd_10: hex!["11 22 33 44"],
            })
    }
}