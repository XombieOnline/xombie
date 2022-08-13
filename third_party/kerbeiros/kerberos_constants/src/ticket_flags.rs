//! Flags used by `Ticket` in Kerberos protocol.
//!
//! # References
//! * RFC 4120, Section 5.3.
//! * RFC 6806, Section 11

pub const RESERVED: u32 = 0x80000000;
pub const FORWARDABLE: u32 = 0x40000000;
pub const FORWARDED: u32 = 0x20000000;
pub const PROXIABLE: u32 = 0x10000000;
pub const PROXY: u32 = 0x08000000;
pub const MAY_POSTDATE: u32 = 0x04000000;
pub const POSTDATE: u32 = 0x02000000;
pub const INVALID: u32 = 0x01000000;
pub const RENEWABLE: u32 = 0x00800000;
pub const INITIAL: u32 = 0x00400000;
pub const PRE_AUTHENT: u32 = 0x00200000;
pub const HW_AUTHENT: u32 = 0x00100000;
pub const TRANSITED_POLICY_CHECKED: u32 = 0x00080000;
pub const OK_AS_DELEGATE: u32 = 0x00040000;

pub const REQUEST_ANONYMOUS: u32 = 0x00020000;
pub const NAME_CANONICALIZE: u32 = 0x00010000;
