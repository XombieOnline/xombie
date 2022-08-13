//! Options used by the message [`AsReq`](../../messages/struct.AsReq.html).

pub const NO_OPTION: u32 = 0x00000000;
pub const FORWARDABLE: u32 = 0x40000000;
pub const FORWARDED: u32 = 0x20000000;
pub const PROXIABLE: u32 = 0x10000000;
pub const PROXY: u32 = 0x08000000;
pub const ALLOW_POSTDATE: u32 = 0x04000000;
pub const POSTDATED: u32 = 0x02000000;
pub const RENEWABLE: u32 = 0x00800000;
pub const OPT_HARDWARE_AUTH: u32 = 0x00100000;
pub const CONSTRAINED_DELEGATION: u32 = 0x00020000;
pub const CANONICALIZE: u32 = 0x00010000;
pub const REQUEST_ANONYMOUS: u32 = 0x8000;
pub const DISABLE_TRANSITED_CHECK: u32 = 0x20;
pub const RENEWABLE_OK: u32 = 0x10;
pub const ENC_TKT_IN_SKEY: u32 = 0x08;
pub const RENEW: u32 = 0x02;
pub const VALIDATE: u32 = 0x01;
