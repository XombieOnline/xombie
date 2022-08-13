//! Types of names used by Kerberos protocol.
//!
//! # References
//! * RFC 4210, Section 6.2.

/// Name type not known
pub const NT_UNKNOWN: i32 = 0;

/// Just the name of the principal as in DCE, or for users
pub const NT_PRINCIPAL: i32 = 1;

/// Service and other unique instance (krbtgt)
pub const NT_SRV_INST: i32 = 2;

/// Service with host name as instance (telnet, rcommands)
pub const NT_SRV_HST: i32 = 3;

/// Service with host as remaining components
pub const NT_SRV_XHST: i32 = 4;

/// Unique ID
pub const NT_UID: i32 = 5;

/// Encoded X.509 Distinguished name
pub const NT_X500_PRINCIPAL: i32 = 6;

/// Name in form of SMTP email name (e.g., user@example.com)
pub const NT_SMTP_NAME: i32 = 7;

/// Enterprise name - may be mapped to principal name
pub const NT_ENTERPRISE: i32 = 10;

pub const NT_MS_PRINCIPAL: i32 = -128;

pub const NT_MS_PRINCIPAL_AND_ID: i32 = -129;

pub const NT_ENT_PRINCIPAL_AND_ID: i32 = -130;
