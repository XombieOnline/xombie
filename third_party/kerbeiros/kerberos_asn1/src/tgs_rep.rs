use crate::{EncryptedData, Int32, PaData, PrincipalName, Realm, Ticket};
use red_asn1::{Asn1Object, SequenceOf};
use red_asn1_derive::Sequence;

/// (*TGS-REP*) Message returned by KDC in response to TGS-REQ.
/// ```asn1
/// TGS-REP         ::= [APPLICATION 13] KDC-REP
///
/// KDC-REP         ::= SEQUENCE {
///        pvno            [0] INTEGER (5),
///        msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
///        padata          [2] SEQUENCE OF PA-DATA OPTIONAL
///                                -- NOTE: not empty --,
///        crealm          [3] Realm,
///        cname           [4] PrincipalName,
///        ticket          [5] Ticket,
///        enc-part        [6] EncryptedData
///                                -- EncASRepPart or EncTGSRepPart,
///                                -- as appropriate
/// }
/// ```
#[derive(Sequence, Debug, Clone, PartialEq)]
#[seq(application_tag = 13)]
pub struct TgsRep {
    #[seq_field(context_tag = 0)]
    pub pvno: Int32,
    #[seq_field(context_tag = 1)]
    pub msg_type: Int32,
    #[seq_field(context_tag = 2)]
    pub padata: Option<SequenceOf<PaData>>,
    #[seq_field(context_tag = 3)]
    pub crealm: Realm,
    #[seq_field(context_tag = 4)]
    pub cname: PrincipalName,
    #[seq_field(context_tag = 5)]
    pub ticket: Ticket,
    #[seq_field(context_tag = 6)]
    pub enc_part: EncryptedData,
}

impl Default for TgsRep {
    fn default() -> Self {
        return Self {
            pvno: 5,
            msg_type: 13,
            padata: Option::default(),
            crealm: Realm::default(),
            cname: PrincipalName::default(),
            ticket: Ticket::default(),
            enc_part: EncryptedData::default(),
        };
    }
}


