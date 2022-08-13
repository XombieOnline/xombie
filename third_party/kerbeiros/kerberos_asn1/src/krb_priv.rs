use crate::{EncryptedData, Int32};
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*KRB-PRIV*) To send a message securely and privately.
/// Defined RFC4120, section 5.7.1.
/// ```asn1
/// KRB-PRIV        ::= [APPLICATION 21] SEQUENCE {
///        pvno            [0] INTEGER (5),
///        msg-type        [1] INTEGER (21),
///                        -- NOTE: there is no [2] tag
///        enc-part        [3] EncryptedData -- EncKrbPrivPart
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
#[seq(application_tag = 21)]
pub struct KrbPriv {
    #[seq_field(context_tag = 0)]
    pub pvno: Int32,
    #[seq_field(context_tag = 1)]
    pub msg_type: Int32,
    #[seq_field(context_tag = 3)]
    pub enc_part: EncryptedData,
}
