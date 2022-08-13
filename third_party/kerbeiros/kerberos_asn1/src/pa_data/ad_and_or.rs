use crate::{Int32, AuthorizationData};
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*AD-AND-OR*) Type of *AuthorizationData*.
/// Defined in RFC4120, section 5.2.6.3.
/// ```asn1
/// AD-AND-OR               ::= SEQUENCE {
///        condition-count [0] Int32,
///        elements        [1] AuthorizationData
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct AdAndOr {
    #[seq_field(context_tag = 0)]
    pub condition_count: Int32,
    #[seq_field(context_tag = 1)]
    pub elements: AuthorizationData,
}
