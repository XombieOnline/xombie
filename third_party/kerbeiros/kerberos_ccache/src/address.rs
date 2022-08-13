use super::counted_octet_string::CountedOctetString;
use nom::number::complete::be_u16;
use nom::IResult;

/// Represent addresses of Kerberos actors.
/// # Definition
/// ```c
/// address {
///     uint16_t addrtype;
///     counted_octet_string addrdata;
/// };
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct Address {
    pub addrtype: u16,
    pub addrdata: CountedOctetString,
}

impl Address {
    pub fn new(addrtype: u16, addrdata: CountedOctetString) -> Self {
        return Self { addrtype, addrdata };
    }

    /// Build the binary representation
    pub fn build(self) -> Vec<u8> {
        let mut bytes = self.addrtype.to_be_bytes().to_vec();
        bytes.append(&mut self.addrdata.build());
        return bytes;
    }

    /// Creates a new instance from the binary representation
    /// # Error
    /// Returns error when the binary has not the expected format.
    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (rest, addrtype) = be_u16(raw)?;
        let (rest, addrdata) = CountedOctetString::parse(rest)?;

        return Ok((rest, Self::new(addrtype, addrdata)));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::address_types::*;

    #[test]
    fn address_to_bytes() {
        assert_eq!(
            vec![
                0x00, 0x14, 0x00, 0x00, 0x00, 0x0e, 0x4b, 0x49, 0x4e, 0x47,
                0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53
            ],
            Address::new(
                NETBIOS as u16,
                CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec())
            )
            .build()
        )
    }

    #[test]
    fn test_parse_address_from_bytes() {
        assert_eq!(
            Address::new(
                NETBIOS as u16,
                CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec())
            ),
            Address::parse(&[
                0x00, 0x14, 0x00, 0x00, 0x00, 0x0e, 0x4b, 0x49, 0x4e, 0x47,
                0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53
            ])
            .unwrap()
            .1,
        )
    }

    #[test]
    #[should_panic(expected = "[0], Eof")]
    fn test_parse_address_from_bytes_panic() {
        Address::parse(&[0x0]).unwrap();
    }
}
