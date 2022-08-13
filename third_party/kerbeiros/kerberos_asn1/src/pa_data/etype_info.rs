use crate::EtypeInfoEntry;
use red_asn1::SequenceOf;

/// (*ETYPE-INFO*) Sent in *KRB-ERROR* to require additional pre-authentication.
/// Defined RFC4120, section 5.2.7.4.
/// ```asn1
/// ETYPE-INFO              ::= SEQUENCE OF ETYPE-INFO-ENTRY
/// ```
pub type EtypeInfo = SequenceOf<EtypeInfoEntry>;
