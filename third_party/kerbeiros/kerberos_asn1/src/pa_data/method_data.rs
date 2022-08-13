use crate::PaData;
use red_asn1::SequenceOf;

/// (*METHOD-DATA*) Sequence of *PA-DATA*.
/// Defined in RFC4120, section 5.9.1.
/// ```asn1
/// METHOD-DATA     ::= SEQUENCE OF PA-DATA
/// ```
pub type MethodData = SequenceOf<PaData>;
