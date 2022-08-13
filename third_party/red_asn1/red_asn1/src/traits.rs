use crate::tag::{Tag, TagClass};
use crate::error as asn1err;
use crate::length::{build_length, parse_length};

/// A trait to allow objects to be built/parsed from ASN1-DER
pub trait Asn1Object: Sized + Default {

    /// Method to retrieve the tag of the object, used to identify each object in ASN1
    fn tag() -> Tag;

    /// Method which indicates how object value must be built
    fn build_value(&self) -> Vec<u8>;

    /// Method which indicates how object value must be parsed
    fn parse_value(&mut self, raw: &[u8]) -> asn1err::Result<()>;

    /// To encode the object to DER, generally does not need to be overwritten.
    /// Usually, just encode_value should be overwritten
    fn build(&self) -> Vec<u8> {
        let mut encoded = Self::tag().build();
        let mut encoded_value = self.build_value();
        let mut encoded_length = build_length(encoded_value.len());

        encoded.append(&mut encoded_length);
        encoded.append(&mut encoded_value);

        return encoded;
    }

    /// To parse the object from DER, generally does not need to be overwritten.
    /// Usually, just parse_value should be overwritten
    fn parse(raw: &[u8]) -> asn1err::Result<(&[u8], Self)> {
        let (raw, parsed_tag) = Tag::parse(raw)?;
        if parsed_tag != Self::tag() {
            return Err(asn1err::Error::UnmatchedTag(TagClass::Universal))?;
        }

        let (raw, length) = parse_length(raw)?;
        if length > raw.len() {
            return Err(asn1err::Error::NoDataForLength)?;
        }

        let (raw_value, raw) = raw.split_at(length);
        let mut asn1obj = Self::default();
        asn1obj.parse_value(raw_value)?;

        return Ok((raw, asn1obj));
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestObject {
    }

    impl TestObject {}

    impl Asn1Object for TestObject {
        fn tag() -> Tag {
            return Tag::default();
        }
        fn build_value(&self) -> Vec<u8> {
            return vec![];
        }

        fn parse_value(&mut self, _raw: &[u8]) -> asn1err::Result<()> {
            return Ok(());
        }

    }

    #[should_panic (expected = "NoDataForLength")]
    #[test]
    fn test_parse_with_excesive_length_for_data() {
        TestObject::parse(&[0x0, 0x3, 0x0]).unwrap();
    }

}
