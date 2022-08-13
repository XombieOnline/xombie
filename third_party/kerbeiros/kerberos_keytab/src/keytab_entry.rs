use super::{CountedOctetString, KeyBlock};
use nom::multi::many_m_n;
use nom::number::complete::{be_i32, be_u16, be_u32, be_u8};
use nom::bytes::complete::take;
use nom::IResult;

/// Definition:
/// ```c
/// keytab_entry {
///     int32_t size;
///     uint16_t num_components;    /* sub 1 if version 0x501 */
///     counted_octet_string realm;
///     counted_octet_string components[num_components];
///     uint32_t name_type;   /* not present if version 0x501 */
///     uint32_t timestamp;
///     uint8_t vno8;
///     keyblock key;
///     uint32_t vno; /* only present if >= 4 bytes left in entry */
/// }
///```
///

#[derive(Clone, Debug, PartialEq)]
pub struct KeytabEntry {
    pub realm: CountedOctetString,
    pub components: Vec<CountedOctetString>,
    pub name_type: u32,
    pub timestamp: u32,
    pub vno8: u8,
    pub key: KeyBlock,
    pub vno: Option<u32>,
}

impl KeytabEntry {
    pub fn new(
        realm: CountedOctetString,
        components: Vec<CountedOctetString>,
        name_type: u32,
        timestamp: u32,
        vno8: u8,
        key: KeyBlock,
        vno: Option<u32>,
    ) -> Self {
        return Self {
            realm,
            components,
            name_type,
            timestamp,
            vno8,
            key,
            vno,
        };
    }

    /// Creates a new instance from the binary representation
    /// # Error
    /// Returns error when the binary has not the expected format.
    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (raw, size) = be_i32(raw)?;

        // negative size means that the entry is deleted
        if size < 0 {
            let (raw, _) = take(-size as usize)(raw)?;
            return Ok((raw, Self::default()));
        }

        let (raw, raw_entry) = take (size as usize)(raw)?;

        let (raw_entry, num_components) = be_u16(raw_entry)?;
        let (raw_entry, realm) = CountedOctetString::parse(raw_entry)?;

        let (raw_entry, components) = many_m_n(
            num_components as usize,
            num_components as usize,
            CountedOctetString::parse,
        )(raw_entry)?;

        let (raw_entry, name_type) = be_u32(raw_entry)?;
        let (raw_entry, timestamp) = be_u32(raw_entry)?;
        let (raw_entry, vno8) = be_u8(raw_entry)?;
        let (raw_entry, key) = KeyBlock::parse(raw_entry)?;

        let vno;
        if raw_entry.len() > 0 {
            let (_, v) = be_u32(raw_entry)?;
            vno = Some(v);
        }else  {
            vno = None;
        }

        return Ok((
            raw,
            Self::new(realm, components, name_type, timestamp, vno8, key, vno),
        ));
    }

    /// Build the binary representation
    pub fn build(self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let num_components = self.components.len() as u16;

        bytes.append(&mut num_components.to_be_bytes().to_vec());
        bytes.append(&mut self.realm.build());

        for component in self.components {
            bytes.append(&mut component.build());
        }

        bytes.append(&mut self.name_type.to_be_bytes().to_vec());
        bytes.append(&mut self.timestamp.to_be_bytes().to_vec());
        bytes.append(&mut self.vno8.to_be_bytes().to_vec());
        bytes.append(&mut self.key.build());

        if let Some(vno) = self.vno {
            bytes.append(&mut vno.to_be_bytes().to_vec());
        }

        let size = bytes.len() as i32;

        let mut size_bytes = size.to_be_bytes().to_vec();
        size_bytes.append(&mut bytes);

        return size_bytes;
    }
}

impl Default for KeytabEntry {

    fn default() -> Self {
        return Self::new(CountedOctetString::default(), Vec::new(), 0, 0, 0, KeyBlock::default(), Some(0));
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    static RAW_ENTRY: &'static [u8] = &[
        0x00, 0x00, 0x00, 0x35, 0x00, 0x01, 0x00, 0x0a, 0x64, 0x6f, 0x6d, 0x61,
        0x69, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x04, 0x75, 0x73, 0x65, 0x72,
        0x00, 0x00, 0x00, 0x01, 0x60, 0x04, 0x57, 0x1f, 0x01, 0x00, 0x17, 0x00,
        0x10, 0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06, 0xbd,
        0xd8, 0x30, 0xb7, 0x58, 0x6c, 0x00, 0x00, 0x00, 0x01,
    ];

    static RAW_ENTRY_NO_VNO: &'static [u8] = &[
        0x00, 0x00, 0x00, 0x31, 0x00, 0x01, 0x00, 0x0a, 0x64, 0x6f, 0x6d, 0x61,
        0x69, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x04, 0x75, 0x73, 0x65, 0x72,
        0x00, 0x00, 0x00, 0x01, 0x60, 0x04, 0x57, 0x1f, 0x01, 0x00, 0x17, 0x00,
        0x10, 0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06, 0xbd,
        0xd8, 0x30, 0xb7, 0x58, 0x6c,
    ];

    #[test]
    fn test_parse_keytab_entry() {
        let entry = KeytabEntry {
            realm: CountedOctetString::new("domain.com".as_bytes().to_vec()),
            components: vec![CountedOctetString::new(
                "user".as_bytes().to_vec(),
            )],
            name_type: 1,
            timestamp: 0x6004571f,
            vno8: 1,
            key: KeyBlock::new(
                0x0017,
                vec![
                    0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06,
                    0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c,
                ],
            ),
            vno: Some(0x00000001),
        };

        assert_eq!(entry, KeytabEntry::parse(RAW_ENTRY).unwrap().1);
    }

    #[test]
    fn test_parse_keytab_entry_no_vno() {
        let entry = KeytabEntry {
            realm: CountedOctetString::new("domain.com".as_bytes().to_vec()),
            components: vec![CountedOctetString::new(
                "user".as_bytes().to_vec(),
            )],
            name_type: 1,
            timestamp: 0x6004571f,
            vno8: 1,
            key: KeyBlock::new(
                0x0017,
                vec![
                    0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06,
                    0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c,
                ],
            ),
            vno: None,
        };

        assert_eq!(entry, KeytabEntry::parse(RAW_ENTRY_NO_VNO).unwrap().1);
    }

    #[test]
    fn test_build_keytab_entry() {
        let entry = KeytabEntry {
            realm: CountedOctetString::new("domain.com".as_bytes().to_vec()),
            components: vec![CountedOctetString::new(
                "user".as_bytes().to_vec(),
            )],
            name_type: 1,
            timestamp: 0x6004571f,
            vno8: 1,
            key: KeyBlock::new(
                0x0017,
                vec![
                    0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06,
                    0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c,
                ],
            ),
            vno: Some(0x00000001),
        };

        assert_eq!(RAW_ENTRY.to_vec(), entry.build());
    }

    #[test]
    fn test_build_keytab_entry_no_vno() {
        let entry = KeytabEntry {
            realm: CountedOctetString::new("domain.com".as_bytes().to_vec()),
            components: vec![CountedOctetString::new(
                "user".as_bytes().to_vec(),
            )],
            name_type: 1,
            timestamp: 0x6004571f,
            vno8: 1,
            key: KeyBlock::new(
                0x0017,
                vec![
                    0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06,
                    0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c,
                ],
            ),
            vno: None,
        };

        assert_eq!(RAW_ENTRY_NO_VNO.to_vec(), entry.build());
    }
}
