use crate::{HostAddress, KerberosTime, KrbCredInfo, Microseconds, UInt32};
use red_asn1::{Asn1Object, SequenceOf};
use red_asn1_derive::Sequence;

/// (*EncKrbCredPart*) The encrypted part of the *KRB-CRED* message. Defined in RFC4120, section 5.8.1.
/// ```asn1
/// EncKrbCredPart  ::= [APPLICATION 29] SEQUENCE {
///        ticket-info     [0] SEQUENCE OF KrbCredInfo,
///        nonce           [1] UInt32 OPTIONAL,
///        timestamp       [2] KerberosTime OPTIONAL,
///        usec            [3] Microseconds OPTIONAL,
///        s-address       [4] HostAddress OPTIONAL,
///        r-address       [5] HostAddress OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
#[seq(application_tag = 29)]
pub struct EncKrbCredPart {
    #[seq_field(context_tag = 0)]
    pub ticket_info: SequenceOf<KrbCredInfo>,
    #[seq_field(context_tag = 1)]
    pub nonce: Option<UInt32>,
    #[seq_field(context_tag = 2)]
    pub timestamp: Option<KerberosTime>,
    #[seq_field(context_tag = 3)]
    pub usec: Option<Microseconds>,
    #[seq_field(context_tag = 4)]
    pub s_address: Option<HostAddress>,
    #[seq_field(context_tag = 5)]
    pub r_address: Option<HostAddress>,
}
