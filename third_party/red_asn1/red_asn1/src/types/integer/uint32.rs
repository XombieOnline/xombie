use super::general::{build_integer_value, parse_uinteger_value};
use crate::error as asn1err;
use super::int_trait::Asn1Int;

impl Asn1Int for u32 {
    fn build_int_value(&self) -> Vec<u8> {
        return build_integer_value(*self as i32 as i128);
    }

    fn parse_int_value(raw: &[u8]) -> asn1err::Result<Self> {
        let value = parse_uinteger_value(raw, 4)?;
        return Ok(value as u32);
    }
}

#[cfg(test)]
mod tests {
    use crate::traits::Asn1Object;

    #[test]
    fn test_build() {
        assert_eq!(vec![0x2, 0x1, 0x0], (0 as u32).build());
        assert_eq!(vec![0x2, 0x1, 0x1], (1 as u32).build());
        assert_eq!(vec![0x2, 0x1, 0xff], ((-1i32) as u32).build());

        assert_eq!(vec![0x2, 0x1, 0x7F], (127 as u32).build());
        assert_eq!(vec![0x2, 0x2, 0x00, 0x80], (128 as u32).build());
        assert_eq!(vec![0x2, 0x2, 0x01, 0x00], (256 as u32).build());
        assert_eq!(vec![0x2, 0x1, 0x80], (-128i32 as u32).build());
        assert_eq!(vec![0x2, 0x2, 0xFF, 0x7F], (-129i32 as u32).build());

        assert_eq!(
            vec![0x2, 0x4, 0xF8, 0x45, 0x33, 0x8],
            (4165284616 as u32).build()
        );
    }

    #[test]
    fn test_parse() {
        assert_eq!((0 as u32), u32::parse(&[0x2, 0x1, 0x0]).unwrap().1);
        assert_eq!((1 as u32), u32::parse(&[0x2, 0x1, 0x1]).unwrap().1);
        assert_eq!((-1i32 as u32), u32::parse(&[0x2, 0x1, 0xff]).unwrap().1);

        assert_eq!((127 as u32), u32::parse(&[0x2, 0x1, 0x7F]).unwrap().1);
        assert_eq!(
            u32::from(128u32),
            u32::parse(&[0x2, 0x2, 0x00, 0x80]).unwrap().1
        );
        assert_eq!(
            u32::from(256u32),
            u32::parse(&[0x2, 0x2, 0x01, 0x00]).unwrap().1
        );
        assert_eq!((-128i32 as u32), u32::parse(&[0x2, 0x1, 0x80]).unwrap().1);
        assert_eq!(
            (-129i32 as u32),
            u32::parse(&[0x2, 0x2, 0xFF, 0x7F]).unwrap().1
        );

        assert_eq!(
            (4165284616u32),
            u32::parse(&[0x2, 0x4, 0xF8, 0x45, 0x33, 0x8]).unwrap().1
        );
    }

    #[test]
    fn test_parse_with_excesive_bytes() {
        let x: &[u8] = &[0x22];
        assert_eq!((x, (0)), u32::parse(&[0x2, 0x1, 0x0, 0x22]).unwrap());
        assert_eq!((x, (1)), u32::parse(&[0x2, 0x1, 0x1, 0x22]).unwrap());
        assert_eq!(
            (x, (-1i32 as u32)),
            u32::parse(&[0x2, 0x1, 0xff, 0x22]).unwrap()
        );

        assert_eq!((x, (127)), u32::parse(&[0x2, 0x1, 0x7F, 0x22]).unwrap());
        assert_eq!(
            (x, (128)),
            u32::parse(&[0x2, 0x2, 0x00, 0x80, 0x22]).unwrap()
        );
        assert_eq!(
            (x, (256u32)),
            u32::parse(&[0x2, 0x2, 0x01, 0x00, 0x22]).unwrap()
        );
        assert_eq!(
            (x, (-128i32 as u32)),
            u32::parse(&[0x2, 0x1, 0x80, 0x22]).unwrap()
        );
        assert_eq!(
            (x, (-129i32 as u32)),
            u32::parse(&[0x2, 0x2, 0xFF, 0x7F, 0x22]).unwrap()
        );

        assert_eq!(
            (x, (4165284616u32)),
            u32::parse(&[0x2, 0x4, 0xF8, 0x45, 0x33, 0x8, 0x22]).unwrap()
        );
    }

    #[should_panic(expected = "UnmatchedTag")]
    #[test]
    fn test_parse_with_invalid_tag() {
        u32::parse(&[0x7, 0x1, 0x0]).unwrap();
    }

    #[should_panic(expected = "IncorrectValue(\"No octets for u32\")")]
    #[test]
    fn test_parse_without_enough_value_octets() {
        u32::parse(&[0x2, 0x0]).unwrap();
    }

    #[should_panic(
        expected = "IncorrectValue(\"Too many octets for u32: 9 octets\")"
    )]
    #[test]
    fn test_parse_with_too_much_value_octets() {
        u32::parse(&[0x2, 9, 0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8])
            .unwrap();
    }

    #[test]
    fn test_parse_with_the_limit_of_value_octets() {
        u32::parse(&[0x2, 4, 0, 0x1, 0x2, 0x3]).unwrap();
    }

    #[test]
    fn test_parse_with_emtpy_fifth_byte() {
        u32::parse(&[0x2, 5, 0, 0x80, 0, 0, 0]).unwrap();
    }

    #[should_panic(
        expected = "IncorrectValue(\"Non zero extra octet for u32\")"
    )]
    #[test]
    fn test_parse_with_non_empty_fifth_byte() {
        u32::parse(&[0x2, 5, 1, 0x80, 0, 0, 0]).unwrap();
    }
}
