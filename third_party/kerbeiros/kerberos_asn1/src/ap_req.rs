use crate::{Int32, ApOptions, Ticket, EncryptedData};
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;
use kerberos_constants::message_types::KRB_AP_REQ;
use kerberos_constants::protocol_version::PVNO;

/// (*AP-REQ*) Message sent to the application server to authenticate the client.
/// Defined in RFC4120, section 5.5.1.
///```asn1
/// AP-REQ          ::= [APPLICATION 14] SEQUENCE {
///        pvno            [0] INTEGER (5),
///        msg-type        [1] INTEGER (14),
///        ap-options      [2] APOptions,
///        ticket          [3] Ticket,
///        authenticator   [4] EncryptedData -- Authenticator
/// }
/// ```
#[derive(Sequence, Debug, Clone, PartialEq)]
#[seq(application_tag = 14)]
pub struct ApReq {
    #[seq_field(context_tag = 0)]
    pub pvno: Int32,
    #[seq_field(context_tag = 1)]
    pub msg_type: Int32,
    #[seq_field(context_tag = 2)]
    pub ap_options: ApOptions,
    #[seq_field(context_tag = 3)]
    pub ticket: Ticket,
    #[seq_field(context_tag = 4)]
    pub authenticator: EncryptedData
}

impl Default for ApReq {
    fn default() -> Self {
        Self {
            pvno: PVNO,
            msg_type: KRB_AP_REQ,
            ap_options: ApOptions::default(),
            ticket: Ticket::default(),
            authenticator: EncryptedData::default()
        }
    }
}
