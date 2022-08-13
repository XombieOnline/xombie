use crate::EncryptionKey;
use red_asn1::SequenceOf;

/// (*KERB-KEY-LIST-REP*) Contains a list of key types the KDC has
/// supplied to the client to support single sign-on capabilities in
/// legacy protocols. Defined in MS-KILE, section 2.2.12.
/// ```asn1
/// KERB-KEY-LIST-REP ::= SEQUENCE OF EncryptionKey
/// ```
pub type KerbKeyListRep = SequenceOf<EncryptionKey>;
