use super::KeytabEntry;
use nom::multi::many0;
use nom::number::complete::be_u8;
use nom::IResult;

/// ```c
/// keytab {
///     uint16_t file_format_version;  /* 0x502 */
///     keytab_entry entries[*];
/// };
/// ```

#[derive(Clone, Debug, PartialEq)]
pub struct Keytab {
    pub kversion: u8,
    pub version: u8,
    pub entries: Vec<KeytabEntry>,
}

impl Keytab {
    pub fn new(kversion: u8, version: u8, entries: Vec<KeytabEntry>) -> Self {
        return Self {
            kversion,
            version,
            entries,
        };
    }

    pub fn build(self) -> Vec<u8> {
        let mut bytes = self.kversion.to_be_bytes().to_vec();

        bytes.append(&mut self.version.to_be_bytes().to_vec());

        for entry in self.entries {
            bytes.append(&mut entry.build())
        }

        return bytes;
    }

    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (rest, kversion) = be_u8(raw)?;
        let (rest, version) = be_u8(rest)?;
        let (rest, entries) = many0(KeytabEntry::parse)(rest)?;

        return Ok((rest, Self::new(kversion, version, entries)));
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CountedOctetString, KeyBlock};
    use super::*;

    static RAW_KEYTAB: &'static [u8] = &[
        0x05, 0x02, 0x00, 0x00, 0x00, 0x35, 0x00, 0x01, 0x00, 0x0a, 0x64, 0x6f,
        0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x04, 0x75, 0x73,
        0x65, 0x72, 0x00, 0x00, 0x00, 0x01, 0x60, 0x04, 0x57, 0x1f, 0x01, 0x00,
        0x17, 0x00, 0x10, 0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad,
        0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x36, 0x00, 0x01, 0x00, 0x0a, 0x64, 0x6f, 0x6d, 0x61, 0x69,
        0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x05, 0x75, 0x73, 0x65, 0x72, 0x32,
        0x00, 0x00, 0x00, 0x01, 0x60, 0x04, 0x57, 0x1f, 0x01, 0x00, 0x17, 0x00,
        0x10, 0xe2, 0x2e, 0x04, 0x51, 0x9a, 0xa7, 0x57, 0xd1, 0x2f, 0x12, 0x19,
        0xc4, 0xf3, 0x12, 0x52, 0xf4, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn test_parse_keytab() {
        let keytab = Keytab {
            kversion: 5,
            version: 2,
            entries: vec![
                KeytabEntry {
                    realm: CountedOctetString::new(
                        "domain.com".as_bytes().to_vec(),
                    ),
                    components: vec![CountedOctetString::new(
                        "user".as_bytes().to_vec(),
                    )],
                    name_type: 1,
                    timestamp: 0x6004571f,
                    vno8: 1,
                    key: KeyBlock::new(
                        0x0017,
                        vec![
                            0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17,
                            0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c,
                        ],
                    ),
                    vno: Some(0x00000001),
                },
                KeytabEntry {
                    realm: CountedOctetString::new(
                        "domain.com".as_bytes().to_vec(),
                    ),
                    components: vec![CountedOctetString::new(
                        "user2".as_bytes().to_vec(),
                    )],
                    name_type: 1,
                    timestamp: 0x6004571f,
                    vno8: 1,
                    key: KeyBlock::new(
                        0x0017,
                        vec![
                            0xe2, 0x2e, 0x04, 0x51, 0x9a, 0xa7, 0x57, 0xd1,
                            0x2f, 0x12, 0x19, 0xc4, 0xf3, 0x12, 0x52, 0xf4,
                        ],
                    ),
                    vno: Some(0x00000001),
                },
            ],
        };

        assert_eq!(keytab, Keytab::parse(RAW_KEYTAB).unwrap().1);
    }


    #[test]
    fn test_build_keytab() {
        let keytab = Keytab {
            kversion: 5,
            version: 2,
            entries: vec![
                KeytabEntry {
                    realm: CountedOctetString::new(
                        "domain.com".as_bytes().to_vec(),
                    ),
                    components: vec![CountedOctetString::new(
                        "user".as_bytes().to_vec(),
                    )],
                    name_type: 1,
                    timestamp: 0x6004571f,
                    vno8: 1,
                    key: KeyBlock::new(
                        0x0017,
                        vec![
                            0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17,
                            0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c,
                        ],
                    ),
                    vno: Some(0x00000001),
                },
                KeytabEntry {
                    realm: CountedOctetString::new(
                        "domain.com".as_bytes().to_vec(),
                    ),
                    components: vec![CountedOctetString::new(
                        "user2".as_bytes().to_vec(),
                    )],
                    name_type: 1,
                    timestamp: 0x6004571f,
                    vno8: 1,
                    key: KeyBlock::new(
                        0x0017,
                        vec![
                            0xe2, 0x2e, 0x04, 0x51, 0x9a, 0xa7, 0x57, 0xd1,
                            0x2f, 0x12, 0x19, 0xc4, 0xf3, 0x12, 0x52, 0xf4,
                        ],
                    ),
                    vno: Some(0x00000001),
                },
            ],
        };

        assert_eq!(RAW_KEYTAB.to_vec(), keytab.build());
    }
}
