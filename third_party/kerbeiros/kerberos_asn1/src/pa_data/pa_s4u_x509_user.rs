use crate::{Checksum, S4uUserId};
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*PA-S4U-X509-USER*) Used in S4U2Self, to specify the user certificate.
/// Defined MS-SFU, section 2.2.2.
/// ```asn1
/// PA-S4U-X509-USER::= SEQUENCE {
///    user-id[0] S4UUserID,
///    checksum[1] Checksum
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct PaS4uX509User {
    #[seq_field(context_tag = 0)]
    pub user_id: S4uUserId,
    #[seq_field(context_tag = 1)]
    pub checksum: Checksum,
}
