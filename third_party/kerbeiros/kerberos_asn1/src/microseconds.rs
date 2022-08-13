
/// (*Microseconds*) Kerberos Microseconds.
/// Defined in RFC4120, section 5.2.4.
/// ```asn1
/// Microseconds    ::= INTEGER (0..999999)
///                    -- microseconds
/// ```
/// The value must be between 0 and 999999.
pub type Microseconds = i32;

pub const MAX_MICROSECONDS: i32 = 999999;
pub const MIN_MICROSECONDS: i32 = 0;
