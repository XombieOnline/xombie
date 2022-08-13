use crate::error as asn1err;
use crate::tag::Tag;
use crate::traits::Asn1Object;

pub static SEQUENCE_TAG_NUMBER: u8 = 0x10;

/// Class to build/parse SequenceOf ASN1
pub type SequenceOf<T> = Vec<T>;

impl<T: Asn1Object> Asn1Object for Vec<T> {
    fn tag() -> Tag {
        return Tag::new_constructed_universal(SEQUENCE_TAG_NUMBER);
    }

    fn build_value(&self) -> Vec<u8> {
        let mut value: Vec<u8> = Vec::new();
        for item in self.iter() {
            value.append(&mut item.build())
        }
        return value;
    }

    fn parse_value(&mut self, raw: &[u8]) -> asn1err::Result<()> {
        let mut components: Vec<T> = Vec::new();
        let mut raw = raw;

        while !raw.is_empty() {
            let (raw_tmp, component) = T::parse(raw)?;
            raw = raw_tmp;
            components.push(component);
        }

        *self = components;
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::super::integer::{Integer, INTEGER_TAG_NUMBER};
    use super::*;

    #[test]
    fn test_build_sequence_of_integers() {
        let mut seq_of: SequenceOf<Integer> = SequenceOf::default();
        seq_of.push(Integer::from(9));
        seq_of.push(Integer::from(1000));

        assert_eq!(
            vec![
                0x30,
                0x7,
                INTEGER_TAG_NUMBER,
                0x1,
                0x9,
                INTEGER_TAG_NUMBER,
                0x2,
                0x3,
                0xe8
            ],
            seq_of.build()
        );
    }

    #[test]
    fn test_build_empty_sequence_of() {
        let seq_of: SequenceOf<Integer> = SequenceOf::default();

        assert_eq!(vec![0x30, 0x0], seq_of.build());
    }

    #[test]
    fn test_parse_sequence_of_integers() {
        let (_, seq_of) = SequenceOf::<Integer>::parse(&[
            0x30,
            0x7,
            INTEGER_TAG_NUMBER,
            0x1,
            0x9,
            INTEGER_TAG_NUMBER,
            0x2,
            0x3,
            0xe8,
        ])
        .unwrap();

        assert_eq!(Integer::from(9), seq_of[0]);
        assert_eq!(Integer::from(1000), seq_of[1]);
    }

    #[test]
    fn test_parse_empty_sequence() {
        let (_, seq_of) = SequenceOf::<Integer>::parse(&[0x30, 0x0]).unwrap();
        assert_eq!(0, seq_of.len());
    }

    #[test]
    fn test_parse_integers_with_excesive_bytes() {
        let raw = [
            0x30,
            0x7,
            INTEGER_TAG_NUMBER,
            0x1,
            0x9,
            INTEGER_TAG_NUMBER,
            0x2,
            0x3,
            0xe8,
            0xff,
            0xff,
        ];
        let (rest, seq_of) = SequenceOf::<Integer>::parse(&raw).unwrap();

        let x: &[u8] = &[0xff, 0xff];
        assert_eq!(x, rest);
        assert_eq!(Integer::from(9), seq_of[0]);
        assert_eq!(Integer::from(1000), seq_of[1]);
    }

    #[should_panic(expected = "UnmatchedTag")]
    #[test]
    fn test_parse_with_invalid_sequence_of_tag() {
        SequenceOf::<Integer>::parse(&[0xff, 0x0]).unwrap();
    }

    #[should_panic(expected = "UnmatchedTag")]
    #[test]
    fn test_parse_with_invalid_inner_type_tag() {
        SequenceOf::<Integer>::parse(&[0x30, 0x3, 0xff, 0x1, 0x9]).unwrap();
    }
}
