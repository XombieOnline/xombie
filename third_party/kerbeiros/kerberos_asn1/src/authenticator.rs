use crate::{
    AuthorizationData, Checksum, EncryptionKey, Int32, KerberosTime,
    Microseconds, PrincipalName, Realm, UInt32,
};
use chrono::{Timelike, Utc};
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*Authenticator*) Included in *AP-REQ* to certified the knowledge of the session key.
/// Defined in RFC4120, section 5.5.1.
/// ```asn1
/// -- Unencrypted authenticator
/// Authenticator   ::= [APPLICATION 2] SEQUENCE  {
///        authenticator-vno       [0] INTEGER (5),
///        crealm                  [1] Realm,
///        cname                   [2] PrincipalName,
///        cksum                   [3] Checksum OPTIONAL,
///        cusec                   [4] Microseconds,
///        ctime                   [5] KerberosTime,
///        subkey                  [6] EncryptionKey OPTIONAL,
///        seq-number              [7] UInt32 OPTIONAL,
///        authorization-data      [8] AuthorizationData OPTIONAL
/// }
/// ```
#[derive(Sequence, Debug, Clone, PartialEq)]
#[seq(application_tag = 2)]
pub struct Authenticator {
    #[seq_field(context_tag = 0)]
    pub authenticator_vno: Int32,
    #[seq_field(context_tag = 1)]
    pub crealm: Realm,
    #[seq_field(context_tag = 2)]
    pub cname: PrincipalName,
    #[seq_field(context_tag = 3)]
    pub cksum: Option<Checksum>,
    #[seq_field(context_tag = 4)]
    pub cusec: Microseconds,
    #[seq_field(context_tag = 5)]
    pub ctime: KerberosTime,
    #[seq_field(context_tag = 6)]
    pub subkey: Option<EncryptionKey>,
    #[seq_field(context_tag = 7)]
    pub seq_number: Option<UInt32>,
    #[seq_field(context_tag = 8)]
    pub authorization_data: Option<AuthorizationData>,
}

impl Default for Authenticator {
    fn default() -> Authenticator {
        let now = Utc::now();
        Self {
            authenticator_vno: 5,
            crealm: Realm::default(),
            cname: PrincipalName::default(),
            cksum: Option::default(),
            cusec: (now.nanosecond() / 1000) as i32,
            ctime: now.into(),
            subkey: Option::default(),
            seq_number: Option::default(),
            authorization_data: Option::default(),
        }
    }
}
