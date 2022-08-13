use super::general::{build_integer_value, parse_integer_value};
use super::int_trait::Asn1Int;
use crate::error as asn1err;
use std::convert::TryInto;

impl Asn1Int for i16 {
    fn build_int_value(&self) -> Vec<u8> {
        return build_integer_value(*self as i128);
    }

    fn parse_int_value(raw: &[u8]) -> asn1err::Result<Self> {
        let value = parse_integer_value(raw, 2)?;
        return Ok(value.try_into().expect("Error parsing i16, too much data"));
    }
}

#[cfg(test)]
mod tests {
    use crate::traits::Asn1Object;

    #[test]
    fn test_build() {
        assert_eq!(vec![0x2, 0x1, 0x0], 0i16.build());
        assert_eq!(vec![0x2, 0x1, 0x1], 1i16.build());
        assert_eq!(vec![0x2, 0x1, 0xff], (-1i16).build());

        assert_eq!(vec![0x2, 0x1, 0x7F], (127i16).build());
        assert_eq!(vec![0x2, 0x2, 0x00, 0x80], (128i16).build());
        assert_eq!(vec![0x2, 0x2, 0x01, 0x00], (256i16).build());
        assert_eq!(vec![0x2, 0x1, 0x80], (-128i16).build());
        assert_eq!(vec![0x2, 0x2, 0xFF, 0x7F], (-129i16).build());
    }

    #[test]
    fn test_parse() {
        assert_eq!(0i16, i16::parse(&[0x2, 0x1, 0x0]).unwrap().1);
        assert_eq!(1i16, i16::parse(&[0x2, 0x1, 0x1]).unwrap().1);
        assert_eq!(-1i16, i16::parse(&[0x2, 0x1, 0xff]).unwrap().1);

        assert_eq!((127i16), i16::parse(&[0x2, 0x1, 0x7F]).unwrap().1);
        assert_eq!((128i16), i16::parse(&[0x2, 0x2, 0x00, 0x80]).unwrap().1);
        assert_eq!((256i16), i16::parse(&[0x2, 0x2, 0x01, 0x00]).unwrap().1);
        assert_eq!((-128i16), i16::parse(&[0x2, 0x1, 0x80]).unwrap().1);
        assert_eq!((-129i16), i16::parse(&[0x2, 0x2, 0xFF, 0x7F]).unwrap().1);
    }

    #[test]
    fn test_parse_with_excesive_bytes() {
        let x: &[u8] = &[0x22];
        assert_eq!((x, (0i16)), i16::parse(&[0x2, 0x1, 0x0, 0x22]).unwrap());
        assert_eq!((x, (1i16)), i16::parse(&[0x2, 0x1, 0x1, 0x22]).unwrap());
        assert_eq!((x, (-1i16)), i16::parse(&[0x2, 0x1, 0xff, 0x22]).unwrap());

        assert_eq!((x, (127i16)), i16::parse(&[0x2, 0x1, 0x7F, 0x22]).unwrap());
        assert_eq!(
            (x, (128i16)),
            i16::parse(&[0x2, 0x2, 0x00, 0x80, 0x22]).unwrap()
        );
        assert_eq!(
            (x, (256i16)),
            i16::parse(&[0x2, 0x2, 0x01, 0x00, 0x22]).unwrap()
        );
        assert_eq!(
            (x, (-128i16)),
            i16::parse(&[0x2, 0x1, 0x80, 0x22]).unwrap()
        );
        assert_eq!(
            (x, (-129i16)),
            i16::parse(&[0x2, 0x2, 0xFF, 0x7F, 0x22]).unwrap()
        );
    }

    #[should_panic(expected = "UnmatchedTag")]
    #[test]
    fn test_parse_with_invalid_tag() {
        i16::parse(&[0x7, 0x1, 0x0]).unwrap();
    }

    #[should_panic(expected = "IncorrectValue(\"No octets for i16\")")]
    #[test]
    fn test_parse_without_enough_value_octets() {
        i16::parse(&[0x2, 0x0]).unwrap();
    }

    #[should_panic(
        expected = "IncorrectValue(\"Too many octets for i16: 3 octets\")"
    )]
    #[test]
    fn test_parse_wit_too_much_value_octets() {
        i16::parse(&[0x2, 3, 0, 0x1, 0x2]).unwrap();
    }

    #[test]
    fn test_parse_with_the_limit_of_value_octets() {
        i16::parse(&[0x2, 2, 0, 0x1]).unwrap();
    }
}
