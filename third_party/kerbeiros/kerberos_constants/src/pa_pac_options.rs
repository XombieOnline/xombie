//! Options used by the PA-PAC-OPTIONS struct
//!
//! # References
//! * MS-KILE, Section 2.2.10.
//! * MS-SFU, Section 2.2.5.

pub const CLAIMS: u32 = 0x80000000;
pub const BRANCH_AWARE: u32 = 0x40000000;
pub const FORWARD_TO_FULL_DC: u32 = 0x20000000;
pub const RESOURCE_BASED_CONSTRAINED_DELEGATION: u32 = 0x10000000;
