use crate::KerberosFlags;

/// (*KDCOptions*) Options used in Kerberos requests.
/// ```asn1
/// KDCOptions      ::= KerberosFlags
///        -- reserved(0),
///        -- forwardable(1),
///        -- forwarded(2),
///        -- proxiable(3),
///        -- proxy(4),
///        -- allow-postdate(5),
///        -- postdated(6),
///        -- unused7(7),
///        -- renewable(8),
///        -- unused9(9),
///        -- unused10(10),
///        -- opt-hardware-auth(11),
///        -- unused12(12),
///        -- unused13(13),
/// -- 15 is reserved for canonicalize
///         -- unused15(15),
/// -- 26 was unused in 1510
///         -- disable-transited-check(26),
/// --
///        -- renewable-ok(27),
///        -- enc-tkt-in-skey(28),
///        -- renew(30),
///        -- validate(31)
/// ```
pub type KdcOptions = KerberosFlags;

