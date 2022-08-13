use crate::error as asn1err;
use crate::tag::Tag;
use crate::traits::Asn1Object;

pub static BOOLEAN_TAG_NUMBER: u8 = 0x1;

/// Class to build/parse Boolean ASN1
pub type Boolean = bool;

impl Asn1Object for bool {
    fn tag() -> Tag {
        return Tag::new_primitive_universal(BOOLEAN_TAG_NUMBER);
    }

    fn build_value(&self) -> Vec<u8> {
        return vec![(*self as u8) * 0xff];
    }

    fn parse_value(&mut self, raw: &[u8]) -> asn1err::Result<()> {
        if raw.len() == 0 {
            return Err(asn1err::Error::IncorrectValue(
                format!("No octects for bool")
            ))?;
        }

        *self = raw[0] != 0;
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build() {
        assert_eq!(vec![0x1, 0x1, 0x0], false.build());
        assert_eq!(vec![0x1, 0x1, 0xff], true.build());
    }

    #[test]
    fn test_parse() {
        assert_eq!(false, bool::parse(&[0x1, 0x1, 0x0]).unwrap().1);
        assert_eq!(true, bool::parse(&[0x1, 0x1, 0xff]).unwrap().1);
        assert_eq!(true, bool::parse(&[0x1, 0x1, 0x01]).unwrap().1);
        assert_eq!(true, bool::parse(&[0x1, 0x1, 0x7b]).unwrap().1);
    }

    #[test]
    fn test_parse_with_excesive_bytes() {
        let x: &[u8] = &[0x1];
        assert_eq!((x, false), bool::parse(&[0x1, 0x1, 0x0, 0x1]).unwrap());
        assert_eq!(
            (x, true),
            bool::parse(&[0x1, 0x1, 0xff, 0x1]).unwrap()
        );
        assert_eq!(
            (x, true),
            bool::parse(&[0x1, 0x1, 0x01, 0x1]).unwrap()
        );
        assert_eq!(
            (x, true),
            bool::parse(&[0x1, 0x1, 0x7b, 0x1]).unwrap()
        );

        let y: &[u8] = &[];
        assert_eq!((y, false), bool::parse(&[0x1, 0x2, 0x0, 0x1]).unwrap());
    }

    #[should_panic(expected = "UnmatchedTag")]
    #[test]
    fn test_parse_with_invalid_tag() {
        bool::parse(&[0x7, 0x1, 0x0]).unwrap();
    }

    #[should_panic(expected = "IncorrectValue(\"No octects for bool\")")]
    #[test]
    fn test_parse_without_enough_value_octets() {
        bool::parse(&[0x1, 0x0]).unwrap();
    }
}
