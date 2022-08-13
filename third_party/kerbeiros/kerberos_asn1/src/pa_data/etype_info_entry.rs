use crate::Int32;
use red_asn1::{Asn1Object, OctetString};
use red_asn1_derive::Sequence;

/// (*ETYPE-INFO-ENTRY*) Entry of *ETYPE-INFO*.
/// Defined RFC4120, section 5.2.7.4.
/// ```asn1
/// ETYPE-INFO-ENTRY        ::= SEQUENCE {
///        etype           [0] Int32,
///        salt            [1] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct EtypeInfoEntry {
    #[seq_field(context_tag = 0)]
    pub etype: Int32,
    #[seq_field(context_tag = 1)]
    pub salt: Option<OctetString>,
}
