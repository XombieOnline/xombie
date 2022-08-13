use crate::KerberosFlags;

/// (*ApOptions*) Options used in *AP-REQ*.
/// Defined in RFC4120, section 5.5.1.
/// ```asn1
/// APOptions       ::= KerberosFlags
///        -- reserved(0),
///        -- use-session-key(1),
///        -- mutual-required(2)
/// ```
pub type ApOptions = KerberosFlags;
