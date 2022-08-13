use crate::error as asn1err;
use crate::tag::Tag;
use crate::traits::Asn1Object;
use ascii::{AsciiChar, AsciiString};

pub static IA5STRING_TAG_NUMBER: u8 = 0x16;

/// Class to build/parse IA5String ASN1
pub type IA5String = AsciiString;

impl Asn1Object for AsciiString {
    fn tag() -> Tag {
        return Tag::new_primitive_universal(IA5STRING_TAG_NUMBER);
    }

    fn build_value(&self) -> Vec<u8> {
        let mut encoded_value: Vec<u8> = Vec::with_capacity(self.len());

        for ch in self.chars() {
            encoded_value.push(ch as u8);
        }

        return encoded_value;
    }

    fn parse_value(&mut self, raw: &[u8]) -> asn1err::Result<()> {
        let mut value = AsciiString::with_capacity(raw.len());

        for byte in raw.iter() {
            value.push(AsciiChar::from_ascii(*byte)?);
        }

        *self = value;

        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ia5string() {
        assert_eq!(
            vec![
                0x16, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x40, 0x72, 0x73,
                0x61, 0x2e, 0x63, 0x6f, 0x6d
            ],
            IA5String::from_ascii("test1@rsa.com").unwrap().build()
        );
    }

    #[test]
    fn test_parse() {
        assert_eq!(
            IA5String::from_ascii("test1@rsa.com").unwrap(),
            IA5String::parse(&[
                0x16, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x40, 0x72, 0x73,
                0x61, 0x2e, 0x63, 0x6f, 0x6d
            ])
            .unwrap()
            .1
        );
    }

    #[test]
    fn test_parse_empty_value() {
        assert_eq!(
            IA5String::from_ascii("").unwrap(),
            IA5String::parse(&[0x16, 0x00]).unwrap().1
        );
    }

    #[test]
    fn test_parse_with_excesive_bytes() {
        let rest: &[u8] = &[0x22, 0x22, 0x22];
        assert_eq!(
            (rest, IA5String::from_ascii("test1@rsa.com").unwrap()),
            IA5String::parse(&[
                0x16, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x40, 0x72, 0x73,
                0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x22, 0x22, 0x22
            ])
            .unwrap()
        );
    }

    #[should_panic(expected = "UnmatchedTag")]
    #[test]
    fn test_parse_with_invalid_tag() {
        IA5String::parse(&[0x7, 0x1, 0x0]).unwrap();
    }

    #[should_panic(expected = "AsciiError")]
    #[test]
    fn test_parse_non_ascii_characters() {
        IA5String::parse(&[0x16, 0x1, 0x80]).unwrap();
    }
}
