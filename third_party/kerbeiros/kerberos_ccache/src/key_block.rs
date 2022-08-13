use nom::number::complete::be_u16;
use nom::IResult;
use nom::{length_data, named};

named!(parse_length_array, length_data!(be_u16));

/// Represents the session key.
/// # Definition
/// ```c
/// keyblock {
///     uint16_t keytype;
///     uint16_t etype; /* only present if version 0x0503 */
///     uint16_t keylen;
///     uint8_t keyvalue[keylen];
/// };
/// ```
///
#[derive(Debug, PartialEq, Clone)]
pub struct KeyBlock {
    pub keytype: u16,
    pub etype: u16,
    pub keyvalue: Vec<u8>,
}

impl KeyBlock {
    pub fn new(keytype: u16, keyvalue: Vec<u8>) -> Self {
        return Self {
            keytype,
            etype: 0,
            keyvalue,
        };
    }

    /// Build the binary representation
    pub fn build(&self) -> Vec<u8> {
        let mut bytes = self.keytype.to_be_bytes().to_vec();
        bytes.append(&mut self.etype.to_be_bytes().to_vec());
        let keylen = self.keyvalue.len() as u16;
        bytes.append(&mut keylen.to_be_bytes().to_vec());
        bytes.append(&mut self.keyvalue.clone());

        return bytes;
    }

    /// Creates a new instance from the binary representation
    /// # Error
    /// Returns error when the binary has not the expected format.
    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (rest, keytype) = be_u16(raw)?;
        let (rest, etype) = be_u16(rest)?;
        let (rest, keyvalue) = parse_length_array(rest)?;

        let mut key_block = Self::new(keytype, keyvalue.to_vec());
        key_block.etype = etype;

        return Ok((rest, key_block));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::etypes::*;

    #[test]
    fn keyblock_to_bytes() {
        assert_eq!(
            vec![
                0x00, 0x12, 0x00, 0x00, 0x00, 0x20, 0x01, 0x27, 0x59, 0x90,
                0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36, 0x95, 0x7c, 0x32, 0xc9,
                0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd, 0x9d, 0x64, 0xcf, 0x28,
                0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91, 0xd4, 0xc2,
            ],
            KeyBlock::new(
                AES256_CTS_HMAC_SHA1_96 as u16,
                vec![
                    0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                    0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                    0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                    0xd4, 0xc2
                ]
            )
            .build()
        )
    }

    #[test]
    fn test_parse_keyblock_from_bytes() {
        assert_eq!(
            KeyBlock::new(
                AES256_CTS_HMAC_SHA1_96 as u16,
                vec![
                    0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                    0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                    0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                    0xd4, 0xc2
                ]
            ),
            KeyBlock::parse(&[
                0x00, 0x12, 0x00, 0x00, 0x00, 0x20, 0x01, 0x27, 0x59, 0x90,
                0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36, 0x95, 0x7c, 0x32, 0xc9,
                0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd, 0x9d, 0x64, 0xcf, 0x28,
                0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91, 0xd4, 0xc2,
            ])
            .unwrap()
            .1
        )
    }

    #[test]
    #[should_panic(expected = "[0], Eof")]
    fn test_parse_keyblock_from_bytes_panic() {
        KeyBlock::parse(&[0x00]).unwrap();
    }
}
