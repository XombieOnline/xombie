use crate::{
    EncAsRepPart, EncTgsRepPart, EncryptionKey, HostAddresses, KerberosTime,
    LastReq, PaData, PrincipalName, Realm, TicketFlags, UInt32,
};
use red_asn1::{Asn1Object, SequenceOf};
use red_asn1_derive::Sequence;

/// (*EncKdcRepPart*) Holds the data that is encrypted
/// in [KdcRep](./struct.KdcRep.html)
///
/// ```asn1
/// EncKDCRepPart   ::= SEQUENCE {
///        key                [0] EncryptionKey,
///        last-req           [1] LastReq,
///        nonce              [2] UInt32,
///        key-expiration     [3] KerberosTime OPTIONAL,
///        flags              [4] TicketFlags,
///        authtime           [5] KerberosTime,
///        starttime          [6] KerberosTime OPTIONAL,
///        endtime            [7] KerberosTime,
///        renew-till         [8] KerberosTime OPTIONAL,
///        srealm             [9] Realm,
///        sname             [10] PrincipalName,
///        caddr             [11] HostAddresses OPTIONAL
///        encrypted-pa-data [12] SEQUENCE OF PA-DATA OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Debug, PartialEq, Clone)]
pub struct EncKdcRepPart {
    #[seq_field(context_tag = 0)]
    pub key: EncryptionKey,
    #[seq_field(context_tag = 1)]
    pub last_req: LastReq,
    #[seq_field(context_tag = 2)]
    pub nonce: UInt32,
    #[seq_field(context_tag = 3)]
    pub key_expiration: Option<KerberosTime>,
    #[seq_field(context_tag = 4)]
    pub flags: TicketFlags,
    #[seq_field(context_tag = 5)]
    pub authtime: KerberosTime,
    #[seq_field(context_tag = 6)]
    pub starttime: Option<KerberosTime>,
    #[seq_field(context_tag = 7)]
    pub endtime: KerberosTime,
    #[seq_field(context_tag = 8)]
    pub renew_till: Option<KerberosTime>,
    #[seq_field(context_tag = 9)]
    pub srealm: Realm,
    #[seq_field(context_tag = 10)]
    pub sname: PrincipalName,
    #[seq_field(context_tag = 11)]
    pub caddr: Option<HostAddresses>,
    #[seq_field(context_tag = 12)]
    pub encrypted_pa_data: Option<SequenceOf<PaData>>,
}

impl From<EncAsRepPart> for EncKdcRepPart {
    fn from(rep_part: EncAsRepPart) -> Self {
        Self {
            key: rep_part.key,
            last_req: rep_part.last_req,
            nonce: rep_part.nonce,
            key_expiration: rep_part.key_expiration,
            flags: rep_part.flags,
            authtime: rep_part.authtime,
            starttime: rep_part.starttime,
            endtime: rep_part.endtime,
            renew_till: rep_part.renew_till,
            srealm: rep_part.srealm,
            sname: rep_part.sname,
            caddr: rep_part.caddr,
            encrypted_pa_data: rep_part.encrypted_pa_data,
        }
    }
}

impl From<EncTgsRepPart> for EncKdcRepPart {
    fn from(rep_part: EncTgsRepPart) -> Self {
        Self {
            key: rep_part.key,
            last_req: rep_part.last_req,
            nonce: rep_part.nonce,
            key_expiration: rep_part.key_expiration,
            flags: rep_part.flags,
            authtime: rep_part.authtime,
            starttime: rep_part.starttime,
            endtime: rep_part.endtime,
            renew_till: rep_part.renew_till,
            srealm: rep_part.srealm,
            sname: rep_part.sname,
            caddr: rep_part.caddr,
            encrypted_pa_data: rep_part.encrypted_pa_data,
        }
    }
}
