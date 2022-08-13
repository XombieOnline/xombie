use crate::Int32;

/// (*PA-SUPPORTED-ENCTYPES*) specify the encryption types supported.
/// Defined in MS-KILE, section 2.2.8.
/// ```asn1
/// PA-SUPPORTED-ENCTYPES ::= Int32 –Supported Encryption Types Bit Field--
/// ```
pub type PaSupportedEnctypes = Int32;
