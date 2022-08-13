use nom::number::complete::be_u16;
use nom::{length_data, named, IResult};
use std::convert::{From, TryInto};
use std::string::FromUtf8Error;

named!(parse_length_array, length_data!(be_u16));

/// String used by keytab. Different from the one used by ccache
/// since length is u16.
///
/// # Definition
/// ```c
/// counted_octet_string {
///    uint16_t length;
///    uint8_t data[length];
/// };
/// ```
///
///

#[derive(Debug, PartialEq, Clone, Default)]
pub struct CountedOctetString {
    /// The field `data` of `counted_octet_string`. To obtain the field
    /// `length`just do `data.len()`.
    pub data: Vec<u8>,
}

impl CountedOctetString {
    /// Creates new CountedOctetString from the data field.
    pub fn new(data: Vec<u8>) -> Self {
        return CountedOctetString { data };
    }

    /// Build the binary representation
    pub fn build(mut self) -> Vec<u8> {
        let data_len = self.data.len() as u16;
        let mut bytes = data_len.to_be_bytes().to_vec();
        bytes.append(&mut self.data);
        return bytes;
    }

    /// Creates a new instance from the binary representation
    /// # Error
    /// Returns error when the binary has not the expected format.
    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (rest, data) = parse_length_array(raw)?;
        return Ok((rest, Self::new(data.to_vec())));
    }
}

impl From<Vec<u8>> for CountedOctetString {
    fn from(v: Vec<u8>) -> Self {
        return Self::new(v);
    }
}

impl From<&str> for CountedOctetString {
    fn from(string: &str) -> Self {
        return Self::new(string.as_bytes().to_vec());
    }
}

impl TryInto<String> for CountedOctetString {
    type Error = FromUtf8Error;

    fn try_into(self) -> Result<String, Self::Error> {
        return Ok(String::from_utf8(self.data)?);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn create_default_octet_string() {
        let octet_string = CountedOctetString::default();
        assert_eq!(Vec::<u8>::new(), octet_string.data);
    }

    #[test]
    fn counted_octet_string_to_bytes() {
        assert_eq!(
            vec![
                0x00, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f,
                0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53
            ],
            CountedOctetString::from("KINGDOM.HEARTS").build()
        );
    }

    #[test]
    fn test_counted_octet_string_from_bytes() {
        assert_eq!(
            CountedOctetString::from("KINGDOM.HEARTS"),
            CountedOctetString::parse(&[
                0x00, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f,
                0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53
            ])
            .unwrap()
            .1
        );
    }

    #[test]
    #[should_panic(expected = "Eof")]
    fn test_parse_counted_octet_string_from_bytes_panic() {
        CountedOctetString::parse(&[0x00]).unwrap();
    }

    #[test]
    fn test_counted_octet_string_to_string() {
        let string: String =
            CountedOctetString::from("ABC").try_into().unwrap();
        assert_eq!("ABC".to_string(), string)
    }

    #[test]
    #[should_panic(expected = "FromUtf8Error")]
    fn test_counted_octet_string_to_string_panic() {
        let _: String = CountedOctetString::new(vec![0xff]).try_into().unwrap();
    }
}
