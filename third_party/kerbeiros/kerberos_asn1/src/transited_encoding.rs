use crate::{Int32};
use red_asn1::{OctetString, Asn1Object};
use red_asn1_derive::Sequence;

/// (*TransitedEncoding*) Lists the names of the Kerberos realms that took part in the client authentication.
/// Defined in RFC4120, section 5.3.
/// ```asn1
/// -- encoded Transited field
/// TransitedEncoding       ::= SEQUENCE {
///        tr-type         [0] Int32 -- must be registered --,
///        contents        [1] OCTET STRING
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct TransitedEncoding {
    #[seq_field(context_tag = 0)]
    pub tr_type: Int32,
    #[seq_field(context_tag = 1)]
    pub contents: OctetString,
}


