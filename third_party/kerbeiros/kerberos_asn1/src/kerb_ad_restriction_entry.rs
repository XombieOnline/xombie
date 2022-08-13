use crate::Int32;
use red_asn1::{Asn1Object, OctetString};
use red_asn1_derive::Sequence;

/// (*KERB-AD-RESTRICTION-ENTRY*) Specify additional restrictions
/// for the client. Defined in MS-KILE, section 2.2.6.
/// ```asn1
/// KERB-AD-RESTRICTION-ENTRY ::= SEQUENCE {
///     restriction-type  [0] Int32,
///     restriction       [1] OCTET STRING
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct KerbAdRestrictionEntry {
    #[seq_field(context_tag = 0)]
    pub restriction_type: Int32,
    #[seq_field(context_tag = 1)]
    pub restriction: OctetString,
}
