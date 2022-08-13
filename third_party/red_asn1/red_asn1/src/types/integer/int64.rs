use super::general::{build_integer_value, parse_integer_value};
use crate::error as asn1err;
use std::convert::TryInto;
use super::Asn1Int;

impl Asn1Int for i64 {
    fn build_int_value(&self) -> Vec<u8> {
        return build_integer_value(*self as i128);
    }

    fn parse_int_value(raw: &[u8]) -> asn1err::Result<Self> {
        let value = parse_integer_value(raw, 8)?;
        return Ok(value.try_into().expect("Error parsing i64, too much data"));
    }
}

#[cfg(test)]
mod tests {
    use crate::traits::Asn1Object;

    #[test]
    fn test_build() {
        assert_eq!(vec![0x2, 0x1, 0x0], i64::from(0).build());
        assert_eq!(vec![0x2, 0x1, 0x1], i64::from(1).build());
        assert_eq!(vec![0x2, 0x1, 0xff], i64::from(-1).build());

        assert_eq!(vec![0x2, 0x1, 0x7F], i64::from(127).build());
        assert_eq!(vec![0x2, 0x2, 0x00, 0x80], i64::from(128).build());
        assert_eq!(vec![0x2, 0x2, 0x01, 0x00], i64::from(256).build());
        assert_eq!(vec![0x2, 0x1, 0x80], i64::from(-128).build());
        assert_eq!(vec![0x2, 0x2, 0xFF, 0x7F], i64::from(-129).build());

        assert_eq!(
            vec![0x2, 0x5, 0x00, 0xF8, 0x45, 0x33, 0x8],
            i64::from(4165284616i64).build()
        );
        assert_eq!(
            vec![0x2, 0x5, 0xFF, 0x3A, 0xAC, 0x53, 0xDB],
            i64::from(-3310595109i64).build()
        );
    }

    #[test]
    fn test_parse() {
        assert_eq!(i64::from(0), i64::parse(&[0x2, 0x1, 0x0]).unwrap().1);
        assert_eq!(i64::from(1), i64::parse(&[0x2, 0x1, 0x1]).unwrap().1);
        assert_eq!(i64::from(-1), i64::parse(&[0x2, 0x1, 0xff]).unwrap().1);

        assert_eq!(i64::from(127), i64::parse(&[0x2, 0x1, 0x7F]).unwrap().1);
        assert_eq!(
            i64::from(128),
            i64::parse(&[0x2, 0x2, 0x00, 0x80]).unwrap().1
        );
        assert_eq!(
            i64::from(256),
            i64::parse(&[0x2, 0x2, 0x01, 0x00]).unwrap().1
        );
        assert_eq!(i64::from(-128), i64::parse(&[0x2, 0x1, 0x80]).unwrap().1);
        assert_eq!(
            i64::from(-129),
            i64::parse(&[0x2, 0x2, 0xFF, 0x7F]).unwrap().1
        );

        assert_eq!(
            i64::from(4165284616i64),
            i64::parse(&[0x2, 0x5, 0x00, 0xF8, 0x45, 0x33, 0x8])
                .unwrap()
                .1
        );
        assert_eq!(
            i64::from(-3310595109i64),
            i64::parse(&[0x2, 0x5, 0xFF, 0x3A, 0xAC, 0x53, 0xDB])
                .unwrap()
                .1
        );
    }

    #[test]
    fn test_parse_with_excesive_bytes() {
        let x: &[u8] = &[0x22];
        assert_eq!(
            (x, i64::from(0)),
            i64::parse(&[0x2, 0x1, 0x0, 0x22]).unwrap()
        );
        assert_eq!(
            (x, i64::from(1)),
            i64::parse(&[0x2, 0x1, 0x1, 0x22]).unwrap()
        );
        assert_eq!(
            (x, i64::from(-1)),
            i64::parse(&[0x2, 0x1, 0xff, 0x22]).unwrap()
        );

        assert_eq!(
            (x, i64::from(127)),
            i64::parse(&[0x2, 0x1, 0x7F, 0x22]).unwrap()
        );
        assert_eq!(
            (x, i64::from(128)),
            i64::parse(&[0x2, 0x2, 0x00, 0x80, 0x22]).unwrap()
        );
        assert_eq!(
            (x, i64::from(256)),
            i64::parse(&[0x2, 0x2, 0x01, 0x00, 0x22]).unwrap()
        );
        assert_eq!(
            (x, i64::from(-128)),
            i64::parse(&[0x2, 0x1, 0x80, 0x22]).unwrap()
        );
        assert_eq!(
            (x, i64::from(-129)),
            i64::parse(&[0x2, 0x2, 0xFF, 0x7F, 0x22]).unwrap()
        );

        assert_eq!(
            (x, i64::from(4165284616i64)),
            i64::parse(&[0x2, 0x5, 0x00, 0xF8, 0x45, 0x33, 0x8, 0x22])
                .unwrap()
        );
        assert_eq!(
            (x, i64::from(-3310595109i64)),
            i64::parse(&[0x2, 0x5, 0xFF, 0x3A, 0xAC, 0x53, 0xDB, 0x22])
                .unwrap()
        );
    }

    #[should_panic(expected = "UnmatchedTag")]
    #[test]
    fn test_parse_with_invalid_tag() {
        i64::parse(&[0x7, 0x1, 0x0]).unwrap();
    }

    #[should_panic(expected = "IncorrectValue(\"No octets for i64\")")]
    #[test]
    fn test_parse_without_enough_value_octets() {
        i64::parse(&[0x2, 0x0]).unwrap();
    }

    #[should_panic(
        expected = "IncorrectValue(\"Too many octets for i64: 9 octets\")"
    )]
    #[test]
    fn test_parse_with_too_much_value_octets() {
        i64::parse(&[
            0x2, 9, 0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
        ])
        .unwrap();
    }

    #[test]
    fn test_parse_with_the_limit_of_value_octets() {
        i64::parse(&[
            0x2, 8, 0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        ])
        .unwrap();
    }
}
