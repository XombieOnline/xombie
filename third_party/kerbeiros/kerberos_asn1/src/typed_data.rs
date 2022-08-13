use crate::Int32;
use red_asn1::{Asn1Object, OctetString, SequenceOf};
use red_asn1_derive::Sequence;

/// (*TYPED-DATA*) For add information to errors in *KRB-ERROR*.
/// Defined in RFC4120, section 5.9.1.
/// ```asn1
/// TYPED-DATA      ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
///        data-type       [0] Int32,
///        data-value      [1] OCTET STRING OPTIONAL
/// }
/// ```
pub type TypedData = SequenceOf<TypedDataEntry>;

/// Entry of *TYPED-DATA*. Pseudotype type defined in this library for implementation.
/// ```asn1
/// TYPED-DATA      ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
///        data-type       [0] Int32,
///        data-value      [1] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct TypedDataEntry {
    #[seq_field(context_tag = 0)]
    pub data_type: Int32,
    #[seq_field(context_tag = 1)]
    pub data_value: Option<OctetString>,
}
