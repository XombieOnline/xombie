use crate::{KerberosTime, Microseconds, UInt32, HostAddress};
use red_asn1::{OctetString, Asn1Object};
use red_asn1_derive::Sequence;


/// (*EncKrbPrivPart*) Encripted part of the *KRB-PRIV* message. Defined in RFC4120, section 5.7.1.
/// ```asn1
/// EncKrbPrivPart  ::= [APPLICATION 28] SEQUENCE {
///        user-data       [0] OCTET STRING,
///        timestamp       [1] KerberosTime OPTIONAL,
///        usec            [2] Microseconds OPTIONAL,
///        seq-number      [3] UInt32 OPTIONAL,
///        s-address       [4] HostAddress -- sender's addr --,
///        r-address       [5] HostAddress OPTIONAL -- recip's addr
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
#[seq(application_tag = 28)]
pub struct EncKrbPrivPart {
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
