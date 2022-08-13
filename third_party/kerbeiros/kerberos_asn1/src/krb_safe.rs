use crate::{Int32, KrbSafeBody, Checksum};
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;


/// (*KRB-SAFE*) Used to send a tamper-proof message to a peer.
/// Defined in RFC4120, section 5.6.1.
/// ```asn1
/// KRB-SAFE        ::= [APPLICATION 20] SEQUENCE {
///           pvno            [0] INTEGER (5),
///           msg-type        [1] INTEGER (20),
///           safe-body       [2] KRB-SAFE-BODY,
///           cksum           [3] Checksum
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
#[seq(application_tag = 20)]
pub struct KrbSafe {
    #[seq_field(context_tag = 0)]
    pub pvno: Int32,
    #[seq_field(context_tag = 1)]
    pub msg_type: Int32,
    #[seq_field(context_tag = 2)]
    pub safe_body: KrbSafeBody,
    #[seq_field(context_tag = 3)]
    pub cksum: Checksum

}
