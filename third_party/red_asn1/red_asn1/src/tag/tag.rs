use super::{TagClass, TagType};
use crate::error as asn1err;
use nom::number::complete::be_u8;

/// Class to represent DER-ASN1 tags of the different types.
///
/// Each tag is divided into 3 parts:
/// * Class: If tag is of an Primitive or Constructed object
/// * Type: The scope of the object
/// * Number: A distinguished number between objects of the same type and class
///
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct Tag {
    pub number: u8,
    pub r#type: TagType,
    pub class: TagClass,
}

impl Tag {
    /// Creates a new tag from a given number, type and class
    pub fn new(number: u8, r#type: TagType, class: TagClass) -> Tag {
        return Tag {
            number,
            r#type,
            class,
        };
    }

    /// Shorcut of: `Tag::new(tag_number, TagType::Primitive, TagClass::Universal)`
    pub fn new_primitive_universal(number: u8) -> Tag {
        return Tag::new(number, TagType::Primitive, TagClass::Universal);
    }

    /// Shorcut of: `Tag::new(tag_number, TagType::Constructed, TagClass::Universal)`
    pub fn new_constructed_universal(number: u8) -> Tag {
        return Tag::new(number, TagType::Constructed, TagClass::Universal);
    }

    /// Produces an DER version of the tag in bytes
    pub fn build(&self) -> Vec<u8> {
        let mut encoded_tag: u8 = 0;

        encoded_tag += self.class as u8;
        encoded_tag <<= 1;

        encoded_tag += self.r#type as u8;
        encoded_tag <<= 5;

        if self.number <= 30 {
            encoded_tag += self.number;
            return vec![encoded_tag];
        }
        encoded_tag |= 0b11111;

        let mut encoded_tags = vec![encoded_tag];

        let mut next_octet = self.number;

        while next_octet > 127 {
            encoded_tags.push(next_octet | 0b10000000);
            next_octet >>= 7;
        }
        encoded_tags.push(next_octet);

        return encoded_tags;
    }

    /// Set the Tag values from a array of bytes
    pub fn parse(raw: &[u8]) -> asn1err::Result<(&[u8], Self)> {
        let (mut raw, octet) = be_u8(raw).map_err(
            |_: nom::Err<(&[u8], nom::error::ErrorKind)>| {
                asn1err::Error::EmptyTag(TagClass::Universal)
            },
        )?;

        let tag_class = (octet & 0xc0) >> 6;
        let tag_type = (octet & 0x20) >> 5;
        let mut tag_number = octet & 0x1f;

        if tag_number == 0x1f {
            let (raw_tmp, tag_number_long_form) =
                Self::parse_high_tag_number(raw)?;
            tag_number = tag_number_long_form;
            raw = raw_tmp;
        }

        let tag = Self::new(
            tag_number,
            TagType::from(tag_type),
            TagClass::from(tag_class),
        );

        return Ok((raw, tag));
    }

    fn parse_high_tag_number(raw: &[u8]) -> asn1err::Result<(&[u8], u8)> {
        let mut consumed_octets = 1;
        let mut tag_number: u8 = 0;
        let mut raw = raw;
        loop {
            let (raw_tmp, next_octet) = be_u8(raw).map_err(
                |_: nom::Err<(&[u8], nom::error::ErrorKind)>| {
                    asn1err::Error::NotEnoughTagOctets(TagClass::Universal)
                },
            )?;
            raw = raw_tmp;
            tag_number +=
                (next_octet & 0b01111111) << (7 * (consumed_octets - 1));
            if next_octet & 0b10000000 == 0 {
                break;
            }
            consumed_octets += 1;
        }

        return Ok((raw, tag_number));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tag() {
        assert_eq!(
            vec![0x00],
            Tag::new(0, TagType::Primitive, TagClass::Universal).build()
        );
        assert_eq!(
            vec![0x40],
            Tag::new(0, TagType::Primitive, TagClass::Application).build()
        );
        assert_eq!(
            vec![0x80],
            Tag::new(0, TagType::Primitive, TagClass::Context).build()
        );
        assert_eq!(
            vec![0xc0],
            Tag::new(0, TagType::Primitive, TagClass::Private).build()
        );
        assert_eq!(
            vec![0x20],
            Tag::new(0, TagType::Constructed, TagClass::Universal).build()
        );
        assert_eq!(
            vec![0x60],
            Tag::new(0, TagType::Constructed, TagClass::Application).build()
        );
        assert_eq!(
            vec![0xa0],
            Tag::new(0, TagType::Constructed, TagClass::Context).build()
        );
        assert_eq!(
            vec![0xe0],
            Tag::new(0, TagType::Constructed, TagClass::Private).build()
        );

        assert_eq!(
            vec![0x1E],
            Tag::new(30, TagType::Primitive, TagClass::Universal).build()
        );
        assert_eq!(
            vec![0x1F, 0x1F],
            Tag::new(31, TagType::Primitive, TagClass::Universal).build()
        );
        assert_eq!(
            vec![0x1F, 0x7F],
            Tag::new(127, TagType::Primitive, TagClass::Universal).build()
        );
        assert_eq!(
            vec![0x1F, 0x80, 0x01],
            Tag::new(128, TagType::Primitive, TagClass::Universal).build()
        );
        assert_eq!(
            vec![0x1F, 0xFF, 0x01],
            Tag::new(255, TagType::Primitive, TagClass::Universal).build()
        );

        assert_eq!(
            vec![0xdf, 0xc6, 0x01],
            Tag::new(198, TagType::Primitive, TagClass::Private).build()
        );
        assert_eq!(
            vec![0xff, 0x6a],
            Tag::new(106, TagType::Constructed, TagClass::Private).build()
        );
        assert_eq!(
            vec![0x3f, 0x39],
            Tag::new(57, TagType::Constructed, TagClass::Universal).build()
        );
        assert_eq!(
            vec![0xbf, 0x24],
            Tag::new(36, TagType::Constructed, TagClass::Context).build()
        );
        assert_eq!(
            vec![0xf4],
            Tag::new(20, TagType::Constructed, TagClass::Private).build()
        );
        assert_eq!(
            vec![0x6b],
            Tag::new(11, TagType::Constructed, TagClass::Application).build()
        );
    }

    #[test]
    fn test_parse_tag() {
        assert_eq!(
            Tag::new(0, TagType::Primitive, TagClass::Universal),
            _parse_tag(vec![0x00])
        );
        assert_eq!(
            Tag::new(0, TagType::Primitive, TagClass::Application),
            _parse_tag(vec![0x40])
        );
        assert_eq!(
            Tag::new(0, TagType::Primitive, TagClass::Context),
            _parse_tag(vec![0x80])
        );
        assert_eq!(
            Tag::new(0, TagType::Primitive, TagClass::Private),
            _parse_tag(vec![0xc0])
        );
        assert_eq!(
            Tag::new(0, TagType::Constructed, TagClass::Universal),
            _parse_tag(vec![0x20])
        );
        assert_eq!(
            Tag::new(0, TagType::Constructed, TagClass::Application),
            _parse_tag(vec![0x60])
        );
        assert_eq!(
            Tag::new(0, TagType::Constructed, TagClass::Context),
            _parse_tag(vec![0xa0])
        );
        assert_eq!(
            Tag::new(0, TagType::Constructed, TagClass::Private),
            _parse_tag(vec![0xe0])
        );

        assert_eq!(
            Tag::new(30, TagType::Primitive, TagClass::Universal),
            _parse_tag(vec![0x1E])
        );
        assert_eq!(
            Tag::new(31, TagType::Primitive, TagClass::Universal),
            _parse_tag(vec![0x1F, 0x1F])
        );
        assert_eq!(
            Tag::new(127, TagType::Primitive, TagClass::Universal),
            _parse_tag(vec![0x1F, 0x7F])
        );
        assert_eq!(
            Tag::new(128, TagType::Primitive, TagClass::Universal),
            _parse_tag(vec![0x1F, 0x80, 0x01])
        );
        assert_eq!(
            Tag::new(255, TagType::Primitive, TagClass::Universal),
            _parse_tag(vec![0x1F, 0xFF, 0x01])
        );

        assert_eq!(
            Tag::new(198, TagType::Primitive, TagClass::Private),
            _parse_tag(vec![0xdf, 0xc6, 0x01])
        );
        assert_eq!(
            Tag::new(106, TagType::Constructed, TagClass::Private),
            _parse_tag(vec![0xff, 0x6a])
        );
        assert_eq!(
            Tag::new(57, TagType::Constructed, TagClass::Universal),
            _parse_tag(vec![0x3f, 0x39])
        );
        assert_eq!(
            Tag::new(36, TagType::Constructed, TagClass::Context),
            _parse_tag(vec![0xbf, 0x24])
        );
        assert_eq!(
            Tag::new(20, TagType::Constructed, TagClass::Private),
            _parse_tag(vec![0xf4])
        );
        assert_eq!(
            Tag::new(11, TagType::Constructed, TagClass::Application),
            _parse_tag(vec![0x6b])
        );
    }

    #[test]
    fn test_parse_tag_with_excesive_bytes() {
        let x: &[u8] = &[0x1];
        assert_eq!(
            (Tag::new(0, TagType::Primitive, TagClass::Application), x),
            _parse_tag_with_consumed_octets(&[0x40, 0x01])
        );
        assert_eq!(
            (Tag::new(31, TagType::Primitive, TagClass::Universal), x),
            _parse_tag_with_consumed_octets(&[0x1F, 0x1F, 0x01])
        );

        let y: &[u8] = &[0x1, 0x2];
        assert_eq!(
            (Tag::new(198, TagType::Primitive, TagClass::Private), y),
            _parse_tag_with_consumed_octets(&[0xdf, 0xc6, 0x01, 0x01, 0x02])
        );
    }

    #[should_panic(expected = "EmptyTag")]
    #[test]
    fn test_parse_empty_tag() {
        _parse_tag(vec![]);
    }

    #[should_panic(expected = "NotEnoughTagOctets")]
    #[test]
    fn test_parse_invalid_tag_with_unfinished_tag_number() {
        _parse_tag(vec![0x1F, 0x80, 0x81]);
    }

    fn _parse_tag(raw: Vec<u8>) -> Tag {
        let (_, tag) = Tag::parse(&raw).unwrap();
        return tag;
    }

    fn _parse_tag_with_consumed_octets(raw: &[u8]) -> (Tag, &[u8]) {
        let (raw, tag) = Tag::parse(raw).unwrap();
        return (tag, raw);
    }
}
