use std::convert::TryFrom;
use std::convert::TryInto;
use std::num::TryFromIntError;

use crate::error as asn1err;
use crate::tag::Tag;
use crate::traits::Asn1Object;

pub static OID_TAG_NUMBER: u8 = 0x6;

/// Class to build/parse Object Identifiers
#[derive(Debug, PartialEq, Default, Clone)]
pub struct Oid {
    pub value1: u8,
    pub value2: u8,
    pub values: Vec<u64>,
}

impl Oid {
    pub fn new(value1: u8, value2: u8, values: Vec<u64>) -> Self {
        return Self {
            value1,
            value2,
            values,
        };
    }
}

impl Asn1Object for Oid {
    fn tag() -> Tag {
        return Tag::new_primitive_universal(OID_TAG_NUMBER);
    }

    fn build_value(&self) -> Vec<u8> {
        let octet1 = 40 * self.value1 + self.value2;
        let mut octets = vec![octet1];

        for value in self.values.iter() {
            let mut value = *value;
            let mut value_octets = Vec::new();

            let octet = (value & 0x7f) as u8;
            value_octets.insert(0, octet);
            value = value >> 7;

            while value > 0 {
                let octet = (value & 0x7f) as u8 | 0x80;
                value_octets.insert(0, octet);
                value = value >> 7;
            }

            octets.extend(value_octets);
        }

        return octets;
    }

    fn parse_value(&mut self, raw: &[u8]) -> asn1err::Result<()> {
        let mut raw = raw.to_vec();

        let octet0 = if raw.is_empty() { 0 } else { raw.remove(0) };

        self.value1 = match octet0 {
            0..=39 => 0,
            40..=79 => 1,
            _ => 2,
        };
        self.value2 = octet0 - (self.value1 * 40u8);

        let mut current_value = 0;

        for n in raw {
            let v = (n & 0x7f) as u64;
            current_value = (current_value << 7) + v;
            if (n & 0x80) == 0 {
                self.values.push(current_value);
                current_value = 0;
            }
        }

        return Ok(());
    }
}

impl Into<Vec<u64>> for Oid {
    fn into(self) -> Vec<u64> {
        let mut v = vec![self.value1 as u64, self.value2 as u64];
        v.extend(self.values);
        return v;
    }
}

impl TryFrom<Vec<u64>> for Oid {
    type Error = TryFromIntError;

    fn try_from(mut v: Vec<u64>) -> Result<Self, Self::Error> {
        let value1 = if v.is_empty() {
            0
        } else {
            v.remove(0).try_into()?
        };

        let value2 = if v.is_empty() {
            0
        } else {
            v.remove(0).try_into()?
        };

        return Ok(Self::new(value1, value2, v));
    }
}

impl TryFrom<Vec<u32>> for Oid {
    type Error = TryFromIntError;

    fn try_from(mut v: Vec<u32>) -> Result<Self, Self::Error> {
        let value1 = if v.is_empty() {
            0
        } else {
            v.remove(0).try_into()?
        };

        let value2 = if v.is_empty() {
            0
        } else {
            v.remove(0).try_into()?
        };

        return Ok(Self::new(
            value1,
            value2,
            v.into_iter().map(|n| n.into()).collect(),
        ));
    }
}

impl TryFrom<Vec<u16>> for Oid {
    type Error = TryFromIntError;

    fn try_from(mut v: Vec<u16>) -> Result<Self, Self::Error> {
        let value1 = if v.is_empty() {
            0
        } else {
            v.remove(0).try_into()?
        };

        let value2 = if v.is_empty() {
            0
        } else {
            v.remove(0).try_into()?
        };

        return Ok(Self::new(
            value1,
            value2,
            v.into_iter().map(|n| n.into()).collect(),
        ));
    }
}

impl From<Vec<u8>> for Oid {
    fn from(mut v: Vec<u8>) -> Self {
        let value1 = if v.is_empty() { 0 } else { v.remove(0) };
        let value2 = if v.is_empty() { 0 } else { v.remove(0) };

        return Self::new(
            value1,
            value2,
            v.into_iter().map(|n| n.into()).collect(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_oid() {
        assert_eq!(
            vec![0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d],
            Oid::new(1, 2, vec![840, 113549]).build()
        );
    }

    #[test]
    fn test_parse_oid() {
        assert_eq!(
            Oid::new(1, 2, vec![840, 113549]),
            Oid::parse(&[0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d])
                .unwrap()
                .1,
        );
    }

    #[test]
    fn test_try_from_vu64() {
        assert_eq!(
            Oid::new(1, 2, vec![840, 113549]),
            vec![1u64, 2u64, 840u64, 113549u64].try_into().unwrap()
        );
    }

    #[test]
    fn test_try_from_vu32() {
        assert_eq!(
            Oid::new(1, 2, vec![840, 113549]),
            vec![1u32, 2u32, 840u32, 113549u32].try_into().unwrap()
        );
    }

    #[test]
    fn test_try_from_vu16() {
        assert_eq!(
            Oid::new(1, 2, vec![840]),
            vec![1u16, 2u16, 840u16].try_into().unwrap()
        );
    }
}
