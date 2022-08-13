use crate::Int32;
use red_asn1::{Asn1Object, OctetString};
use red_asn1_derive::Sequence;

/// (*Checksum*) Checksum of the related message.
/// Defined in RFC4120, section 5.2.9.
///```asn1
/// Checksum        ::= SEQUENCE {
///        cksumtype       [0] Int32,
///        checksum        [1] OCTET STRING
/// }
///```
#[derive(Sequence, Default, Clone, Debug, PartialEq)]
pub struct Checksum {
    #[seq_field(context_tag = 0)]
    pub cksumtype: Int32,
    #[seq_field(context_tag = 1)]
    pub checksum: OctetString,
}
