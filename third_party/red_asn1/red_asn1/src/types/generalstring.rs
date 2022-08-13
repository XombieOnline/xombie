use crate::error as asn1err;
use crate::tag::Tag;
use crate::traits::Asn1Object;

pub static GENERALSTRING_TAG_NUMBER: u8 = 0x1b;

/// Class to build/parse GeneralString ASN1
pub type GeneralString = String;

impl Asn1Object for String {
    fn tag() -> Tag {
        return Tag::new_primitive_universal(GENERALSTRING_TAG_NUMBER);
    }

    fn build_value(&self) -> Vec<u8> {
        return self.as_bytes().to_vec();
    }

    fn parse_value(&mut self, raw: &[u8]) -> asn1err::Result<()> {
        *self = String::from_utf8(raw.to_vec())?;
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build() {
        assert_eq!(
            vec![
                0x1b, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x40, 0x72, 0x73,
                0x61, 0x2e, 0x63, 0x6f, 0x6d
            ],
            GeneralString::from("test1@rsa.com").build()
        );
    }

    #[test]
    fn test_parse() {
        assert_eq!(
            GeneralString::from("test1@rsa.com"),
            String::parse(&[
                0x1b, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x40, 0x72, 0x73,
                0x61, 0x2e, 0x63, 0x6f, 0x6d
            ])
            .unwrap()
            .1
        );
    }

    #[test]
    fn test_parse_empty_value() {
        assert_eq!(
            GeneralString::from("".to_string()),
            String::parse(&[0x1b, 0x00]).unwrap().1
        );
    }

    #[test]
    fn test_parse_with_excesive_bytes() {
        let rest: &[u8] = &[0x22, 0x22, 0x22];
        assert_eq!(
            (rest, GeneralString::from("test1@rsa.com".to_string())),
            String::parse(&[
                0x1b, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x40, 0x72, 0x73,
                0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x22, 0x22, 0x22
            ])
            .unwrap()
        );
    }

    #[should_panic(expected = "Utf8Error")]
    #[test]
    fn test_parse_non_ascii_characters() {
        String::parse(&[0x1b, 0x1, 0xff]).unwrap();
    }

    #[should_panic(expected = "UnmatchedTag")]
    #[test]
    fn test_parse_with_invalid_tag() {
        String::parse(&[0x7, 0x1, 0x0]).unwrap();
    }
}
