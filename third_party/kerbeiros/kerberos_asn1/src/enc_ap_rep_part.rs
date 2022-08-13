use crate::{KerberosTime, Microseconds, EncryptionKey, UInt32};
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*EncAPRepPart*) Encrypted part of the message *AP-REP*.
/// Defined in RFC4120, section 5.5.2.
/// ```asn1
/// EncAPRepPart    ::= [APPLICATION 27] SEQUENCE {
///        ctime           [0] KerberosTime,
///        cusec           [1] Microseconds,
///        subkey          [2] EncryptionKey OPTIONAL,
///        seq-number      [3] UInt32 OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
#[seq(application_tag = 27)]
pub struct EncApRepPart {
    #[seq_field(context_tag = 0)]
    pub ctime: KerberosTime,
    #[seq_field(context_tag = 1)]
    pub cusec: Microseconds,
    #[seq_field(context_tag = 2)]
    pub subkey: Option<EncryptionKey>,
    #[seq_field(context_tag = 3)]
    pub seq_number: Option<UInt32>,
}
