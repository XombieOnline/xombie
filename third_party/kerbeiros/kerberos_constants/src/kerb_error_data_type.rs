//! Values used in KerbErrorData data_type field.
//!
//! # References
//! * MS-KILE, Section 2.2.2.

/// Clock skew recovery was attempted.
pub const KERB_AP_ERR_TYPE_SKEW_RECOVERY: i32 = 2;

/// The Data-value field contains extended, implementation-specific
/// error information.
pub const KERB_ERR_TYPE_EXTENDED: i32 = 3;
