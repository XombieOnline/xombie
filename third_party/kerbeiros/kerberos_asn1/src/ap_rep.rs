use crate::{Int32, EncryptedData};
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*AP-REP*) Response to *AP-REQ*, sent when mutual authentication is selected.
/// Defined in RFC4120, section 5.5.2.
/// ```asn1
/// AP-REP          ::= [APPLICATION 15] SEQUENCE {
///        pvno            [0] INTEGER (5),
///        msg-type        [1] INTEGER (15),
///        enc-part        [2] EncryptedData -- EncAPRepPart
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
#[seq(application_tag = 15)]
pub struct ApRep {
    #[seq_field(context_tag = 0)]
    pub pvno: Int32,
    #[seq_field(context_tag = 1)]
    pub msg_type: Int32,
    #[seq_field(context_tag = 2)]
    pub enc_part: EncryptedData,
}
