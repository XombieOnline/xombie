use crate::KerberosFlags;

/// (*TicketFlags*) Flags for tickets.
/// ```asn1
/// TicketFlags     ::= KerberosFlags
///        -- reserved(0),
///        -- forwardable(1),
///        -- forwarded(2),
///        -- proxiable(3),
///        -- proxy(4),
///        -- may-postdate(5),
///        -- postdated(6),
///        -- invalid(7),
///        -- renewable(8),
///        -- initial(9),
///        -- pre-authent(10),
///        -- hw-authent(11),
/// -- the following are new since 1510
///        -- transited-policy-checked(12),
///         -- ok-as-delegate(13)
/// ```
pub type TicketFlags = KerberosFlags;

