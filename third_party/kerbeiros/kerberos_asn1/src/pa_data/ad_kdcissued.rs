use crate::{AuthorizationData, Checksum, PrincipalName, Realm};
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*AD-KDCIssued*) Type of *AuthorizationData*.
/// Defined in RFC4120, section 5.2.6.2.
/// ```asn1
/// AD-KDCIssued            ::= SEQUENCE {
///        ad-checksum     [0] Checksum,
///        i-realm         [1] Realm OPTIONAL,
///        i-sname         [2] PrincipalName OPTIONAL,
///        elements        [3] AuthorizationData
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct AdKdcIssued {
    #[seq_field(context_tag = 0)]
    pub ad_checksum: Checksum,
    #[seq_field(context_tag = 1)]
    pub i_realm: Option<Realm>,
    #[seq_field(context_tag = 2)]
    pub i_sname: Option<PrincipalName>,
    #[seq_field(context_tag = 3)]
    pub elements: AuthorizationData,
}
