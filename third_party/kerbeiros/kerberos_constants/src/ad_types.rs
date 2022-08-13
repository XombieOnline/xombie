//! Types of *AuthorizationData*. Specify in the ad-type field.
//! RFC4120, Section 7.5.4.

pub const AD_IF_RELEVANT: i32 = 1;
pub const AD_INTENDED_FOR_SERVER: i32 = 2;
pub const AD_INTENDED_FOR_APPLICATION_CLASS: i32 = 3;
pub const AD_KDCISSUED: i32 = 4;
pub const AD_AND_OR: i32 = 5;
pub const AD_MANDATORY_TICKET_EXTENSIONS: i32 = 6;
pub const AD_IN_TICKET_EXTENSIONS: i32 = 7;
pub const AD_MANDATORY_FOR_KDC: i32 = 8;
pub const OSF_DCE: i32 = 64;
pub const SESAME: i32 = 65;
pub const AD_OSF_DCE_PKI_CERTID: i32 = 66;
pub const AD_WIN2K_PACK: i32 = 128;
pub const AD_ETYPE_NEGOTIATION: i32 = 129;

