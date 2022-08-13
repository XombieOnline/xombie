use crate::error as asn1err;
use crate::tag::Tag;
use crate::traits::Asn1Object;

pub static BIT_STRING_TAG_NUMBER: u8 = 0x3;

/// Class to build/parse BitSring ASN1
#[derive(Debug, PartialEq, Default, Clone)]
pub struct BitString {
    pub bytes: Vec<u8>,
    pub padding_length: u8,
}

impl BitString {
    pub fn new(bytes: Vec<u8>, padding_length: u8) -> Self {
        let mut bs = Self {
            bytes,
            padding_length,
        };

        bs.pad_with_0();
        return bs;
    }

    fn pad_with_0(&mut self) {
        match self.bytes.pop() {
            Some(last_item) => {
                self.bytes
                    .push(Self::set_0_padding(last_item, self.padding_length));
            }
            None => {}
        }
    }

    fn set_0_padding(mut item: u8, padding_length: u8) -> u8 {
        item >>= padding_length;
        item <<= padding_length;
        return item;
    }
}

impl Asn1Object for BitString {
    fn tag() -> Tag {
        return Tag::new_primitive_universal(BIT_STRING_TAG_NUMBER);
    }

    fn build_value(&self) -> Vec<u8> {
        let mut encoded_value: Vec<u8> = vec![self.padding_length];

        let mut values: Vec<u8> = Vec::new();
        let bytes = &self.bytes;
        for i in 0..bytes.len() {
            values.push(bytes[i])
        }
        encoded_value.append(&mut values);

        return encoded_value;
    }

    fn parse_value(&mut self, raw: &[u8]) -> asn1err::Result<()> {
        if raw.len() == 0 {
            return Err(asn1err::Error::IncorrectValue(
                format!("No octects for BitString")
            ))?;
        }

        let (padding_length, raw_value) = raw.split_at(1);

        *self = BitString::new(raw_value.to_vec(), padding_length[0]);

        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_bit_string() {
        assert_eq!(
            vec![0x3, 0x2, 0x0, 0x0],
            BitString::new(vec![0x0], 0).build()
        );
        assert_eq!(
            vec![0x3, 0x4, 0x6, 0x6e, 0x5d, 0xC0],
            BitString::new(vec![0x6e, 0x5d, 0xFF], 6).build()
        );
        assert_eq!(
            vec![0x3, 0x2, 0x4, 0xF0],
            BitString::new(vec![0xF0], 4).build()
        );
        assert_eq!(vec![0x3, 0x1, 0x4], BitString::new(vec![], 4).build());
    }

    #[test]
    fn test_parse() {
        assert_eq!(
            BitString::new(vec![0x0], 0),
            BitString::parse(&[0x3, 0x2, 0x0, 0x0]).unwrap().1
        );
        assert_eq!(
            BitString::new(vec![0x6e, 0x5d, 0xFF], 6),
            BitString::parse(&[0x3, 0x4, 0x6, 0x6e, 0x5d, 0xFF])
                .unwrap()
                .1
        );
        assert_eq!(
            BitString::new(vec![0xF0], 4),
            BitString::parse(&[0x3, 0x2, 0x4, 0xF0]).unwrap().1
        );
        assert_eq!(
            BitString::new(vec![], 4),
            BitString::parse(&[0x3, 0x1, 0x4]).unwrap().1
        );
    }

    #[test]
    fn test_parse_boolean_with_excesive_bytes() {
        let x: &[u8] = &[0x11, 0x22];
        assert_eq!(
            (x, BitString::new(vec![0x0], 0)),
            BitString::parse(&[0x3, 0x2, 0x0, 0x0, 0x11, 0x22]).unwrap()
        );
        assert_eq!(
            (x, BitString::new(vec![0x6e, 0x5d, 0xFF], 6)),
            BitString::parse(&[0x3, 0x4, 0x6, 0x6e, 0x5d, 0xFF, 0x11, 0x22])
                .unwrap()
        );
        assert_eq!(
            (x, BitString::new(vec![0xF0], 4)),
            BitString::parse(&[0x3, 0x2, 0x4, 0xF0, 0x11, 0x22]).unwrap()
        );
        assert_eq!(
            (x, BitString::new(vec![], 4)),
            BitString::parse(&[0x3, 0x1, 0x4, 0x11, 0x22]).unwrap()
        );
    }

    #[should_panic(expected = "UnmatchedTag")]
    #[test]
    fn test_parse_boolean_with_invalid_tag() {
        BitString::parse(&[0x7, 0x1, 0x0]).unwrap();
    }

    #[should_panic(expected = "IncorrectValue(\"No octects for BitString\")")]
    #[test]
    fn test_parse_boolean_without_enough_value_octets() {
        BitString::parse(&[0x3, 0x0]).unwrap();
    }

    #[test]
    fn test_value_get_bytes() {
        let b = BitString::new(vec![0x0, 0x1, 0x2, 0x3], 0);
        assert_eq!(vec![0x0, 0x1, 0x2, 0x3], b.bytes);
    }

    #[test]
    fn test_value_padding_length() {
        let b = BitString::new(vec![0x0, 0x1, 0x2, 0x3], 7);
        assert_eq!(7, b.padding_length);
    }
}
