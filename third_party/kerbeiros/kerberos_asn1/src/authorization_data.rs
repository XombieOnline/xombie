use crate::Int32;
use red_asn1::{OctetString, Asn1Object};
use red_asn1_derive::Sequence;

/// (*AuthorizationData*) Defined in RFC4120, section 5.2.6.
/// ```asn1
/// -- NOTE: AuthorizationData is always used as an OPTIONAL field and
/// -- should not be empty.
/// AuthorizationData       ::= SEQUENCE OF SEQUENCE {
///        ad-type         [0] Int32,
///        ad-data         [1] OCTET STRING
/// }
/// ```
pub type AuthorizationData = Vec<AuthorizationDataEntry>;

/// Entry of the AuthorizationData
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct AuthorizationDataEntry {
    #[seq_field(context_tag = 0)]
    pub ad_type: Int32,
    #[seq_field(context_tag = 1)]
    pub ad_data: OctetString
}
