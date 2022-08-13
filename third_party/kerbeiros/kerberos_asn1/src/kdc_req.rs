use red_asn1::{SequenceOf, Asn1Object};
use red_asn1_derive::Sequence;
use crate::{Int32, PaData, KdcReqBody};
use crate::{AsReq, TgsReq};

/// (*KDC-REQ*) Base for AS-REQ and TGS-REQ
/// ```asn1
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
pub struct KdcReq {
    #[seq_field(context_tag = 1)]
    pub pvno: Int32,
    #[seq_field(context_tag = 2)]
    pub msg_type: Int32,
    #[seq_field(context_tag = 3)]
    pub padata: Option<SequenceOf<PaData>>,
    #[seq_field(context_tag = 4)]
    pub req_body: KdcReqBody,
}

impl Default for KdcReq {
    fn default() -> Self {
        return Self {
            pvno: 5,
            msg_type: Int32::default(),
            padata: Option::default(),
            req_body: KdcReqBody::default()
        }
    }
}

impl From<AsReq> for KdcReq {
    fn from(req: AsReq) -> Self {
        Self {
            pvno: req.pvno,
            msg_type: req.msg_type,
            padata: req.padata,
            req_body: req.req_body
        }
    }
}

impl From<TgsReq> for KdcReq {
    fn from(req: TgsReq) -> Self {
        Self {
            pvno: req.pvno,
            msg_type: req.msg_type,
            padata: req.padata,
            req_body: req.req_body
        }
    }
}
