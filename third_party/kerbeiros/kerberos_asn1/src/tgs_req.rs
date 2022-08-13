use red_asn1::{SequenceOf, Asn1Object};
use red_asn1_derive::Sequence;
use crate::{Int32, PaData, KdcReqBody, KdcReq};

/// (*TGS-REQ*) Message used to request a TGS.
/// ```asn1
/// TGS-REQ         ::= [APPLICATION 12] KDC-REQ
///
/// KDC-REQ         ::= SEQUENCE {
///        -- NOTE: first tag is [1], not [0]
///        pvno            [1] INTEGER (5) ,
///        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
///        padata          [3] SEQUENCE OF PA-DATA OPTIONAL
///                            -- NOTE: not empty --,
///        req-body        [4] KDC-REQ-BODY
/// }
/// ```

#[derive(Sequence, Debug, PartialEq, Clone)]
#[seq(application_tag = 12)]
pub struct TgsReq {
    #[seq_field(context_tag = 1)]
    pub pvno: Int32,
    #[seq_field(context_tag = 2)]
    pub msg_type: Int32,
    #[seq_field(context_tag = 3)]
    pub padata: Option<SequenceOf<PaData>>,
    #[seq_field(context_tag = 4)]
    pub req_body: KdcReqBody,
}

impl Default for TgsReq {
    fn default() -> Self {
        return Self {
            pvno: 5,
            msg_type: 12,
            padata: Option::default(),
            req_body: KdcReqBody::default()
        }
    }
}

impl From<KdcReq> for TgsReq {
    fn from(req: KdcReq) -> Self {
        Self {
            pvno: req.pvno,
            msg_type: 12,
            padata: req.padata,
            req_body: req.req_body
        }
    }
}
