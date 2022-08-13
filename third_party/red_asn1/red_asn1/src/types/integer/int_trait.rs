use crate::INTEGER_TAG_NUMBER;
use crate::Tag;
use crate::Asn1Object;
use crate::error as asn1err;

/// A trait to identify types that are ASN.1 integers
pub trait Asn1Int: Sized + Default {
    fn build_int_value(&self) -> Vec<u8>;
    fn parse_int_value(raw: &[u8]) -> asn1err::Result<Self>;
}


impl<T: Asn1Int> Asn1Object for T {
    fn tag() -> Tag {
        return Tag::new_primitive_universal(INTEGER_TAG_NUMBER);
    }

    fn build_value(&self) -> Vec<u8> {
        return self.build_int_value();
    }

    fn parse_value(&mut self, raw: &[u8]) -> asn1err::Result<()> {
        *self = Self::parse_int_value(raw)?;
        return Ok(());
    }
}
