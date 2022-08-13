use nom::number::complete::be_u16;
use nom::IResult;
use nom::{length_data, named};
use super::DeltaTime;

named!(parse_length_u16_array, length_data!(be_u16));

/// Header of [CCache](./struct.CCache.html)
/// # Definition
/// ```c
/// header {
///     uint16_t tag; /* 1 = DeltaTime */
///     uint16_t taglen;
///     uint8_t tagdata[taglen]
/// };
/// ```
///
#[derive(Debug, PartialEq, Clone)]
pub struct Header {
    pub tag: u16,
    pub tagdata: Vec<u8>,
}

impl Header {
    pub const DELTA_TIME: u16 = 1;

    pub fn new(tag: u16, tagdata: Vec<u8>) -> Self {
        return Self { tag, tagdata };
    }

    /// Build the binary representation
    pub fn build(mut self) -> Vec<u8> {
        let mut bytes = self.tag.to_be_bytes().to_vec();
        let raw_len = self.tagdata.len() as u16;
        bytes.append(&mut raw_len.to_be_bytes().to_vec());
        bytes.append(&mut self.tagdata);
        return bytes;
    }

    /// Creates a new instance from the binary representation
    /// # Error
    /// Returns error when the binary has not the expected format.
    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (raw, tag) = be_u16(raw)?;
        let (raw, tagdata) = parse_length_u16_array(raw)?;
        return Ok((raw, Self::new(tag, tagdata.to_vec())));
    }
}

impl Default for Header {
    fn default() -> Self {
        return Header::new(Header::DELTA_TIME, DeltaTime::default().build());
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn header_to_bytes() {
        assert_eq!(
            vec![
                0x00, 0x01, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
                0x00, 0x00
            ],
            Header::default().build()
        )
    }

    #[test]
    fn test_parse_header() {
        assert_eq!(
            Header::default(),
            Header::parse(&[
                0x00, 0x01, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
                0x00, 0x00
            ])
            .unwrap()
            .1,
        )
    }

    #[test]
    #[should_panic(expected = "[0], Eof")]
    fn test_parse_header_panic() {
        Header::parse(&[0x00]).unwrap();
    }
}
