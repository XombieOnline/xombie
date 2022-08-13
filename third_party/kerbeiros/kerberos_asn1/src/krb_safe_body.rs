use crate::{HostAddress, KerberosTime, Microseconds, UInt32};
use red_asn1::{Asn1Object, OctetString};
use red_asn1_derive::Sequence;

/// (*KRB-SAFE-BODY*) Included in *KRB-SAFE*.
/// Defined in RFC4120, section 5.6.1.
/// ```asn1
/// KRB-SAFE-BODY   ::= SEQUENCE {
///        user-data       [0] OCTET STRING,
///        timestamp       [1] KerberosTime OPTIONAL,
///        usec            [2] Microseconds OPTIONAL,
///        seq-number      [3] UInt32 OPTIONAL,
///        s-address       [4] HostAddress,
///        r-address       [5] HostAddress OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct KrbSafeBody {
    #[seq_field(context_tag = 0)]
    pub user_data: OctetString,
    #[seq_field(context_tag = 1)]
    pub timestamp: Option<KerberosTime>,
    #[seq_field(context_tag = 2)]
    pub usec: Option<Microseconds>,
    #[seq_field(context_tag = 3)]
    pub seq_number: Option<UInt32>,
    #[seq_field(context_tag = 4)]
    pub s_address: HostAddress,
    #[seq_field(context_tag = 5)]
    pub r_address: Option<HostAddress>,
}
