use crate::Int32;
use red_asn1::SequenceOf;

/// (*KERB-KEY-LIST-REQ*) Used to request a list of key types the KDC
/// can supply to the client to support single sign-on capabilities in
/// legacy protocols. Defined in MS-KILE, section 2.2.11.
/// ```asn1
/// KERB-KEY-LIST-REQ ::= SEQUENCE OF Int32 --encryption type --
/// ```
pub type KerbKeyListReq = SequenceOf<Int32>;
