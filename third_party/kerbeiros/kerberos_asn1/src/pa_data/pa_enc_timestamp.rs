use crate::EncryptedData;

/// (*PA-ENC-TIMESTAMP*) Encrypted *PA-ENC-TS-ENC*.
/// Defined in RFC4120, section 5.2.7.2.
/// ```asn1
/// PA-ENC-TIMESTAMP        ::= EncryptedData -- PA-ENC-TS-ENC
/// ```
pub type PaEncTimestamp = EncryptedData;
