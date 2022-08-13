use super::counted_octet_string::CountedOctetString;
use nom::multi::many_m_n;
use nom::number::complete::be_u32;
use nom::IResult;

/// Name of some Kerberos entity.
/// # Definition
/// ```c
/// principal {
///           uint32_t name_type;           /* not present if version 0x0501 */
///           uint32_t num_components;      /* sub 1 if version 0x501 */
///           counted_octet_string realm;
///           counted_octet_string components[num_components];
/// };
/// ```
///
#[derive(Debug, Clone, PartialEq)]
pub struct Principal {
    pub name_type: u32,
    pub realm: CountedOctetString,
    pub components: Vec<CountedOctetString>,
}

impl Principal {
    pub fn new(
        name_type: u32,
        realm: CountedOctetString,
        components: Vec<CountedOctetString>,
    ) -> Self {
        return Self {
            name_type,
            realm,
            components,
        };
    }

    /// Build the binary representation
    pub fn build(self) -> Vec<u8> {
        let mut bytes = self.name_type.to_be_bytes().to_vec();
        let components_len = self.components.len() as u32;

        bytes.append(&mut components_len.to_be_bytes().to_vec());
        bytes.append(&mut self.realm.build());

        for component in self.components.into_iter() {
            bytes.append(&mut component.build());
        }

        return bytes;
    }

    /// Creates a new instance from the binary representation
    /// # Error
    /// Returns error when the binary has not the expected format.
    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (rest, name_type) = be_u32(raw)?;
        let (rest, components_len) = be_u32(rest)?;
        let (rest, realm) = CountedOctetString::parse(rest)?;
        let (rest, components) = many_m_n(
            components_len as usize,
            components_len as usize,
            CountedOctetString::parse,
        )(rest)?;

        return Ok((rest, Self::new(name_type, realm, components)));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::principal_names::*;

    #[test]
    fn principal_to_bytes() {
        assert_eq!(
            vec![
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e,
                0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x00, 0x00, 0x00, 0x06,
                0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79
            ],
            Principal::new(
                NT_PRINCIPAL as u32,
                CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
                vec![CountedOctetString::new("mickey".as_bytes().to_vec())]
            )
            .build()
        );
    }

    #[test]
    fn test_parse_principal_from_bytes() {
        assert_eq!(
            Principal::new(
                NT_PRINCIPAL as u32,
                CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
                vec![CountedOctetString::new("mickey".as_bytes().to_vec())]
            ),
            Principal::parse(&[
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e,
                0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x00, 0x00, 0x00, 0x06,
                0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79
            ])
            .unwrap()
            .1,
        );
    }

    #[test]
    #[should_panic(expected = "[0], Eof")]
    fn test_parse_principal_from_bytes_panic() {
        Principal::parse(&[0x00]).unwrap();
    }
}
