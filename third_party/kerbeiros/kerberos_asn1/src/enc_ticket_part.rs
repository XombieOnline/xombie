use crate::{
    AuthorizationData, EncryptionKey, HostAddresses, KerberosTime,
    PrincipalName, Realm, TicketFlags, TransitedEncoding,
};
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*EncTicketPart*) Encrypted part of a *Ticket*.
/// Defined in RFC4120, section 5.3.
/// ```asn1
/// -- Encrypted part of ticket
/// EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
///        flags                   [0] TicketFlags,
///        key                     [1] EncryptionKey,
///        crealm                  [2] Realm,
///        cname                   [3] PrincipalName,
///        transited               [4] TransitedEncoding,
///        authtime                [5] KerberosTime,
///        starttime               [6] KerberosTime OPTIONAL,
///        endtime                 [7] KerberosTime,
///        renew-till              [8] KerberosTime OPTIONAL,
///        caddr                   [9] HostAddresses OPTIONAL,
///        authorization-data      [10] AuthorizationData OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
#[seq(application_tag = 3)]
pub struct EncTicketPart {
    #[seq_field(context_tag = 0)]
    pub flags: TicketFlags,
    #[seq_field(context_tag = 1)]
    pub key: EncryptionKey,
    #[seq_field(context_tag = 2)]
    pub crealm: Realm,
    #[seq_field(context_tag = 3)]
    pub cname: PrincipalName,
    #[seq_field(context_tag = 4)]
    pub transited: TransitedEncoding,
    #[seq_field(context_tag = 5)]
    pub authtime: KerberosTime,
    #[seq_field(context_tag = 6)]
    pub starttime: Option<KerberosTime>,
    #[seq_field(context_tag = 7)]
    pub endtime: KerberosTime,
    #[seq_field(context_tag = 8)]
    pub renew_till: Option<KerberosTime>,
    #[seq_field(context_tag = 9)]
    pub caddr: Option<HostAddresses>,
    #[seq_field(context_tag = 10)]
    pub authorization_data: Option<AuthorizationData>,
}
