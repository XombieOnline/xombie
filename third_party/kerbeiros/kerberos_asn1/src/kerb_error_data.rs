use crate::Int32;
use red_asn1::{Asn1Object, OctetString};
use red_asn1_derive::Sequence;

/// (*KERB-ERROR-DATA*) returned in e-data field of *KRB-ERROR*.
/// Defined in MS-KILE, section 2.2.2.
/// ```asn1
/// KERB-ERROR-DATA ::= SEQUENCE {
///     data-type    [1] INTEGER,
///     data-value   [2] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct KerbErrorData {
    #[seq_field(context_tag = 1)]
    pub data_type: Int32,
    #[seq_field(context_tag = 2)]
    pub data_value: Option<OctetString>,
}
