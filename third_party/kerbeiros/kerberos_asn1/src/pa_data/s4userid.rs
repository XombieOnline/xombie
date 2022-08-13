use red_asn1::{Asn1Object, OctetString, BitString};
use red_asn1_derive::Sequence;
use crate::{PrincipalName, UInt32, Realm};

/// (*S4UUserID*) Used in *PA-S4U-X509-USER*, to specify the user certificate.
/// Defined in MS-SFU, section 2.2.2.
/// ```asn1
/// S4UUserID ::= SEQUENCE {
///    nonce [0] UInt32, -- the nonce in KDC-REQ-BODY
///    cname [1] PrincipalName OPTIONAL,
///     -- Certificate mapping hints
///     crealm [2] Realm,
///     subject-certificate [3] OCTET STRING OPTIONAL,
///     options [4] BIT STRING OPTIONAL,
///     ...
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct S4uUserId {
    #[seq_field(context_tag = 0)]
    pub nonce: UInt32,
    #[seq_field(context_tag = 1)]
    pub cname: Option<PrincipalName>,
    #[seq_field(context_tag = 2)]
    pub crealm: Realm,
    #[seq_field(context_tag = 3)]
    pub subject_certificate: Option<OctetString>,
    #[seq_field(context_tag = 4)]
    pub options: Option<BitString>,
}
