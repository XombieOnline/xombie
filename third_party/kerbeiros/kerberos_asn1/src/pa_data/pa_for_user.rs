use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;
use crate::{PrincipalName, Realm, Checksum, KerberosString};

/// (*PA-FOR-USER*) Used in S4U2Self, to specify user to impersonate.
/// Defined in MS-SFU, section 2.2.1.
/// ```asn1
/// PA-FOR-USER ::= SEQUENCE {
///    -- PA TYPE 129
///    userName     [0] PrincipalName,
///    userRealm    [1] Realm,
///    cksum        [2] Checksum,
///    auth-package [3] KerberosString
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct PaForUser {
    #[seq_field(context_tag = 0)]
    pub username: PrincipalName,
    #[seq_field(context_tag = 1)]
    pub userrealm: Realm,
    #[seq_field(context_tag = 2)]
    pub cksum: Checksum,
    #[seq_field(context_tag = 3)]
    pub auth_package: KerberosString,
}

