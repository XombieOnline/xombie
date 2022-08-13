use crate::types::integer::Asn1Int;
use crate::error as asn1err;
use crate::tag::Tag;
use crate::traits::Asn1Object;
use std::ops::{Deref, DerefMut};

pub static ENUMERATED_TAG_NUMBER: u8 = 0x0a;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Enumerated<T: Asn1Int>(T);

impl<T: Asn1Int> Enumerated<T> {
    pub fn new(v: T) -> Self {
        return Self(v);
    }
}

impl<T: Asn1Int> Deref for Enumerated<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Asn1Int> DerefMut for Enumerated<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Asn1Int> Asn1Object for Enumerated<T> {
    fn tag() -> Tag {
        return Tag::new_primitive_universal(ENUMERATED_TAG_NUMBER);
    }

    fn build_value(&self) -> Vec<u8> {
        return self.0.build_int_value();
    }

    fn parse_value(&mut self, raw: &[u8]) -> asn1err::Result<()> {
        self.0 = T::parse_int_value(raw)?;
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build() {
        assert_eq!(vec![0xa, 0x1, 0x0], Enumerated::new(0 as u32).build());
        assert_eq!(vec![0xa, 0x1, 0x1], Enumerated::new(1 as u32).build());
        assert_eq!(
            vec![0xa, 0x1, 0xff],
            Enumerated::new((-1i32) as u32).build()
        );

        assert_eq!(vec![0xa, 0x1, 0x7F], Enumerated::new(127 as u32).build());
        assert_eq!(
            vec![0xa, 0x2, 0x00, 0x80],
            Enumerated::new(128 as u32).build()
        );
        assert_eq!(
            vec![0xa, 0x2, 0x01, 0x00],
            Enumerated::new(256 as u32).build()
        );
        assert_eq!(
            vec![0xa, 0x1, 0x80],
            Enumerated::new(-128i32 as u32).build()
        );
        assert_eq!(
            vec![0xa, 0x2, 0xFF, 0x7F],
            Enumerated::new(-129i32 as u32).build()
        );

        assert_eq!(
            vec![0xa, 0x4, 0xF8, 0x45, 0x33, 0x8],
            Enumerated::new(4165284616 as u32).build()
        );
    }

    #[test]
    fn test_parse() {
        assert_eq!(
            Enumerated::new(0 as u32),
            Enumerated::<u32>::parse(&[0xa, 0x1, 0x0]).unwrap().1
        );
        assert_eq!(
            Enumerated::new(1 as u32),
            Enumerated::<u32>::parse(&[0xa, 0x1, 0x1]).unwrap().1
        );
        assert_eq!(
            Enumerated::new(-1i32 as u32),
            Enumerated::<u32>::parse(&[0xa, 0x1, 0xff]).unwrap().1
        );

        assert_eq!(
            Enumerated::new(127 as u32),
            Enumerated::<u32>::parse(&[0xa, 0x1, 0x7F]).unwrap().1
        );
        assert_eq!(
            Enumerated::new(128u32),
            Enumerated::<u32>::parse(&[0xa, 0x2, 0x00, 0x80]).unwrap().1
        );
        assert_eq!(
            Enumerated::new(256u32),
            Enumerated::<u32>::parse(&[0xa, 0x2, 0x01, 0x00]).unwrap().1
        );
        assert_eq!(
            Enumerated::new(-128i32 as u32),
            Enumerated::<u32>::parse(&[0xa, 0x1, 0x80]).unwrap().1
        );
        assert_eq!(
            Enumerated::new(-129i32 as u32),
            Enumerated::<u32>::parse(&[0xa, 0x2, 0xFF, 0x7F]).unwrap().1
        );

        assert_eq!(
            Enumerated::new(4165284616u32),
            Enumerated::<u32>::parse(&[0xa, 0x4, 0xF8, 0x45, 0x33, 0x8])
                .unwrap()
                .1
        );
    }

    #[test]
    fn test_parse_with_excesive_bytes() {
        let x: &[u8] = &[0x22];
        assert_eq!(
            (x, Enumerated::new(0)),
            Enumerated::<u32>::parse(&[0xa, 0x1, 0x0, 0x22]).unwrap()
        );
        assert_eq!(
            (x, Enumerated::new(1)),
            Enumerated::<u32>::parse(&[0xa, 0x1, 0x1, 0x22]).unwrap()
        );
        assert_eq!(
            (x, Enumerated::new(-1i32 as u32)),
            Enumerated::<u32>::parse(&[0xa, 0x1, 0xff, 0x22]).unwrap()
        );

        assert_eq!(
            (x, Enumerated::new(127)),
            Enumerated::<u32>::parse(&[0xa, 0x1, 0x7F, 0x22]).unwrap()
        );
        assert_eq!(
            (x, Enumerated::new(128)),
            Enumerated::<u32>::parse(&[0xa, 0x2, 0x00, 0x80, 0x22]).unwrap()
        );
        assert_eq!(
            (x, Enumerated::new(256u32)),
            Enumerated::<u32>::parse(&[0xa, 0x2, 0x01, 0x00, 0x22]).unwrap()
        );
        assert_eq!(
            (x, Enumerated::new(-128i32 as u32)),
            Enumerated::<u32>::parse(&[0xa, 0x1, 0x80, 0x22]).unwrap()
        );
        assert_eq!(
            (x, Enumerated::new(-129i32 as u32)),
            Enumerated::<u32>::parse(&[0xa, 0x2, 0xFF, 0x7F, 0x22]).unwrap()
        );

        assert_eq!(
            (x, Enumerated::new(4165284616u32)),
            Enumerated::<u32>::parse(&[0xa, 0x4, 0xF8, 0x45, 0x33, 0x8, 0x22])
                .unwrap()
        );
    }

    #[should_panic(expected = "UnmatchedTag")]
    #[test]
    fn test_parse_with_invalid_tag() {
        Enumerated::<u32>::parse(&[0x7, 0x1, 0x0]).unwrap();
    }

    #[should_panic(expected = "IncorrectValue(\"No octets for u32\")")]
    #[test]
    fn test_parse_without_enough_value_octets() {
        Enumerated::<u32>::parse(&[0xa, 0x0]).unwrap();
    }

    #[should_panic(
        expected = "IncorrectValue(\"Too many octets for u32: 9 octets\")"
    )]
    #[test]
    fn test_parse_with_too_much_value_octets() {
        Enumerated::<u32>::parse(&[
            0xa, 9, 0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
        ])
        .unwrap();
    }

    #[test]
    fn test_parse_with_the_limit_of_value_octets() {
        Enumerated::<u32>::parse(&[0xa, 4, 0, 0x1, 0x2, 0x3]).unwrap();
    }
}
