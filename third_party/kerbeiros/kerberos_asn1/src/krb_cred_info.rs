use crate::{
    EncryptionKey, HostAddresses, KerberosTime, PrincipalName, Realm,
    TicketFlags,
};
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*KrbCredInfo*) Information of the ticket sent in *EncKrbCredPart*.
/// Defined in RFC4120, section 5.8.1.
/// ```asn1
/// KrbCredInfo     ::= SEQUENCE {
///        key             [0] EncryptionKey,
///        prealm          [1] Realm OPTIONAL,
///        pname           [2] PrincipalName OPTIONAL,
///        flags           [3] TicketFlags OPTIONAL,
///        authtime        [4] KerberosTime OPTIONAL,
///        starttime       [5] KerberosTime OPTIONAL,
///        endtime         [6] KerberosTime OPTIONAL,
///        renew-till      [7] KerberosTime OPTIONAL,
///        srealm          [8] Realm OPTIONAL,
///        sname           [9] PrincipalName OPTIONAL,
///        caddr           [10] HostAddresses OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct KrbCredInfo {
    #[seq_field(context_tag = 0)]
    pub key: EncryptionKey,
    #[seq_field(context_tag = 1)]
    pub prealm: Option<Realm>,
    #[seq_field(context_tag = 2)]
    pub pname: Option<PrincipalName>,
    #[seq_field(context_tag = 3)]
    pub flags: Option<TicketFlags>,
    #[seq_field(context_tag = 4)]
    pub authtime: Option<KerberosTime>,
    #[seq_field(context_tag = 5)]
    pub starttime: Option<KerberosTime>,
    #[seq_field(context_tag = 6)]
    pub endtime: Option<KerberosTime>,
    #[seq_field(context_tag = 7)]
    pub renew_till: Option<KerberosTime>,
    #[seq_field(context_tag = 8)]
    pub srealm: Option<Realm>,
    #[seq_field(context_tag = 9)]
    pub sname: Option<PrincipalName>,
    #[seq_field(context_tag = 10)]
    pub caddr: Option<HostAddresses>,
}
