//! These constants define the use of keys in Kerberos protocol.
//!
//! # References
//! * RFC 4210, Section 7.5.1.
//! * [MS-KILE] Section 3.1.5.9

/// AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the client key
pub const KEY_USAGE_AS_REQ_TIMESTAMP: u32 = 1;

/// AS-REP Ticket and TGS-REP Ticket (includes TGS session
/// key or application session key), encrypted with the service key
pub const KEY_USAGE_AS_REP_TICKET: u32 = 2;

/// AS-REP encrypted part (includes TGS session key or
/// application session key), encrypted with the client key
pub const KEY_USAGE_AS_REP_ENC_PART: u32 = 3;

/// TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted
/// with the TGS session key
pub const KEY_USAGE_TGS_REQ_AUTH_DATA_SESSION_KEY: u32 = 4;

/// TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted
/// with the TGS authenticator subkey
pub const KEY_USAGE_TGS_REQ_AUTH_DATA_AUTHEN_SUBKEY: u32 = 5;

/// TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator
/// cksum, keyed with the TGS session key
pub const KEY_USAGE_TGS_REQ_AUTHEN_CKSUM: u32 = 6;

/// TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
/// TGS authenticator subkey), encrypted with the TGS session key
pub const KEY_USAGE_TGS_REQ_AUTHEN: u32 = 7;

/// TGS-REP encrypted part (includes application session
/// key), encrypted with the TGS session key
pub const KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY: u32 = 8;

/// TGS-REP encrypted part (includes application session
/// key), encrypted with the TGS authenticator subkey
pub const KEY_USAGE_TGS_REP_ENC_PART_AUTHEN_SUBKEY: u32 = 9;

/// AP-REQ Authenticator cksum, keyed with the application
/// session key
pub const KEY_USAGE_AP_REQ_AUTHEN_CKSUM: u32 = 10;

/// AP-REQ Authenticator (includes application authenticator
/// subkey), encrypted with the application session key
pub const KEY_USAGE_AP_REQ_AUTHEN: u32 = 11;

/// AP-REP encrypted part (includes application session
/// subkey), encrypted with the application session key
pub const KEY_USAGE_AP_REP_ENC_PART: u32 = 12;

/// KRB-PRIV encrypted part, encrypted with a key chosen by
/// the application
pub const KEY_USAGE_KRB_PRIV_ENC_PART: u32 = 13;

/// KRB-CRED encrypted part, encrypted with a key chosen by
/// the application
pub const KEY_USAGE_KRB_CRED_ENC_PART: u32 = 14;

/// KRB-SAFE cksum, keyed with a key chosen by the
/// application
pub const KEY_USAGE_KRB_SAFE_CKSUM: u32 = 15;


pub const KEY_USAGE_KERB_NON_KERB_SALT: u32 = 16;
pub const KEY_USAGE_KERB_NON_KERB_CKSUM_SALT: u32 = 17;
