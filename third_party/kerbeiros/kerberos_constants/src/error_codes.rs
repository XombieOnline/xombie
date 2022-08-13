//! Error codes retrieved by [`KrbError`](../../messages/struct.KrbError.html).
//!
//! Defined in RFC4120, section 7.5.9.

/// No error
pub const KDC_ERR_NONE: i32 = 0;

/// Client's entry in database has expired
pub const KDC_ERR_NAME_EXP: i32 = 1;

/// Server's entry in database has expired
pub const KDC_ERR_SERVICE_EXP: i32 = 2;

/// Requested protocol version number not supported
pub const KDC_ERR_BAD_PVNO: i32 = 3;

/// Client's key encrypted in old master key
pub const KDC_ERR_C_OLD_MAST_KVNO: i32 = 4;

/// Server's key encrypted in old master key
pub const KDC_ERR_S_OLD_MAST_KVNO: i32 = 5;

/// Client not found in Kerberos database
pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;

/// Server not found in Kerberos database
pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;

/// Multiple principal entries in database
pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE: i32 = 8;

/// The client or server has a null key
pub const KDC_ERR_NULL_KEY: i32 = 9;

/// Ticket not eligible for postdating
pub const KDC_ERR_CANNOT_POSTDATE: i32 = 10;

/// Requested starttime is later than end time
pub const KDC_ERR_NEVER_VALID: i32 = 11;

/// KDC policy rejects request
pub const KDC_ERR_POLICY: i32 = 12;

/// KDC cannot accommodate requested option
pub const KDC_ERR_BADOPTION: i32 = 13;

/// KDC has no support for encryption type
pub const KDC_ERR_ETYPE_NOSUPP: i32 = 14;

/// KDC has no support for checksum type
pub const KDC_ERR_SUMTYPE_NOSUPP: i32 = 15;

/// KDC has no support for padata type
pub const KDC_ERR_PADATA_TYPE_NOSUPP: i32 = 16;

/// KDC has no support for transited type
pub const KDC_ERR_TRTYPE_NOSUPP: i32 = 17;

/// Clients credentials have been revoked
pub const KDC_ERR_CLIENT_REVOKED: i32 = 18;

/// Credentials for server have been revoked
pub const KDC_ERR_SERVICE_REVOKED: i32 = 19;

/// TGT has been revoked
pub const KDC_ERR_TGT_REVOKED: i32 = 20;

/// Client not yet valid; try again later
pub const KDC_ERR_CLIENT_NOTYET: i32 = 21;

/// Server not yet valid; try again later
pub const KDC_ERR_SERVICE_NOTYET: i32 = 22;

/// Password has expired; change password to reset
pub const KDC_ERR_KEY_EXPIRED: i32 = 23;

/// Pre-authentication information was invalid
pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;

/// Additional pre- authentication required
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;

/// Requested server and ticket don't match
pub const KDC_ERR_SERVER_NOMATCH: i32 = 26;

/// Server principal valid for user2user only
pub const KDC_ERR_MUST_USE_USER2USER: i32 = 27;

/// KDC Policy rejects transited path
pub const KDC_ERR_PATH_NOT_ACCEPTED: i32 = 28;

/// A service is not available
pub const KDC_ERR_SVC_UNAVAILABLE: i32 = 29;

/// Integrity check on decrypted field failed
pub const KRB_AP_ERR_BAD_INTEGRITY: i32 = 31;

/// Ticket expired
pub const KRB_AP_ERR_TKT_EXPIRED: i32 = 32;

/// Ticket not yet valid
pub const KRB_AP_ERR_TKT_NYV: i32 = 33;

/// Request is a replay
pub const KRB_AP_ERR_REPEAT: i32 = 34;

/// The ticket isn't for us
pub const KRB_AP_ERR_NOT_US: i32 = 35;

/// Ticket and authenticator don't match
pub const KRB_AP_ERR_BADMATCH: i32 = 36;

/// Clock skew too great
pub const KRB_AP_ERR_SKEW: i32 = 37;

/// Incorrect net address
pub const KRB_AP_ERR_BADADDR: i32 = 38;

/// Protocol version mismatch
pub const KRB_AP_ERR_BADVERSION: i32 = 39;

/// Invalid msg type
pub const KRB_AP_ERR_MSG_TYPE: i32 = 40;

/// Message stream modified
pub const KRB_AP_ERR_MODIFIED: i32 = 41;

/// Message out of order
pub const KRB_AP_ERR_BADORDER: i32 = 42;

/// Specified version of key is not available
pub const KRB_AP_ERR_BADKEYVER: i32 = 44;

/// Service key not available
pub const KRB_AP_ERR_NOKEY: i32 = 45;

/// Mutual authentication failed
pub const KRB_AP_ERR_MUT_FAIL: i32 = 46;

/// Incorrect message direction
pub const KRB_AP_ERR_BADDIRECTION: i32 = 47;

/// Alternative authentication method required
pub const KRB_AP_ERR_METHOD: i32 = 48;

/// Incorrect sequence number in message
pub const KRB_AP_ERR_BADSEQ: i32 = 49;

/// Inappropriate type of checksum in message
pub const KRB_AP_ERR_INAPP_CKSUM: i32 = 50;

/// Policy rejects transited path
pub const KRB_AP_PATH_NOT_ACCEPTED: i32 = 51;

/// Response too big for UDP; retry with TCP
pub const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;

/// Generic error (description in e-text)
pub const KRB_ERR_GENERIC: i32 = 60;

/// Field is too long for this implementation
pub const KRB_ERR_FIELD_TOOLONG: i32 = 61;

pub const KDC_ERROR_CLIENT_NOT_TRUSTED: i32 = 62;
pub const KDC_ERROR_KDC_NOT_TRUSTED: i32 = 63;
pub const KDC_ERROR_INVALID_SIG: i32 = 64;
pub const KDC_ERR_KEY_TOO_WEAK: i32 = 65;
pub const KDC_ERR_CERTIFICATE_MISMATCH: i32 = 66;

/// No TGT available to validate USER-TO-USER
pub const KRB_AP_ERR_NO_TGT: i32 = 67;
pub const KDC_ERR_WRONG_REALM: i32 = 68;

/// Ticket must be for USER-TO-USER
pub const KRB_AP_ERR_USER_TO_USER_REQUIRED: i32 = 69;
pub const KDC_ERR_CANT_VERIFY_CERTIFICATE: i32 = 70;
pub const KDC_ERR_INVALID_CERTIFICATE: i32 = 71;
pub const KDC_ERR_REVOKED_CERTIFICATE: i32 = 72;
pub const KDC_ERR_REVOCATION_STATUS_UNKNOWN: i32 = 73;
pub const KDC_ERR_REVOCATION_STATUS_UNAVAILABLE: i32 = 74;
pub const KDC_ERR_CLIENT_NAME_MISMATCH: i32 = 75;
pub const KDC_ERR_KDC_NAME_MISMATCH: i32 = 76;

pub fn error_code_to_string(error_code: i32) -> String {
    match error_code {
        0 => "KDC_ERR_NONE".to_string(),
        1 => "KDC_ERR_NAME_EXP".to_string(),
        2 => "KDC_ERR_SERVICE_EXP".to_string(),
        3 => "KDC_ERR_BAD_PVNO".to_string(),
        4 => "KDC_ERR_C_OLD_MAST_KVNO".to_string(),
        5 => "KDC_ERR_S_OLD_MAST_KVNO".to_string(),
        6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN".to_string(),
        7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN".to_string(),
        8 => "KDC_ERR_PRINCIPAL_NOT_UNIQUE".to_string(),
        9 => "KDC_ERR_NULL_KEY".to_string(),
        10 => "KDC_ERR_CANNOT_POSTDATE".to_string(),
        11 => "KDC_ERR_NEVER_VALID".to_string(),
        12 => "KDC_ERR_POLICY".to_string(),
        13 => "KDC_ERR_BADOPTION".to_string(),
        14 => "KDC_ERR_ETYPE_NOSUPP".to_string(),
        15 => "KDC_ERR_SUMTYPE_NOSUPP".to_string(),
        16 => "KDC_ERR_PADATA_TYPE_NOSUPP".to_string(),
        17 => "KDC_ERR_TRTYPE_NOSUPP".to_string(),
        18 => "KDC_ERR_CLIENT_REVOKED".to_string(),
        19 => "KDC_ERR_SERVICE_REVOKED".to_string(),
        20 => "KDC_ERR_TGT_REVOKED".to_string(),
        21 => "KDC_ERR_CLIENT_NOTYET".to_string(),
        22 => "KDC_ERR_SERVICE_NOTYET".to_string(),
        23 => "KDC_ERR_KEY_EXPIRED".to_string(),
        24 => "KDC_ERR_PREAUTH_FAILED".to_string(),
        25 => "KDC_ERR_PREAUTH_REQUIRED".to_string(),
        26 => "KDC_ERR_SERVER_NOMATCH".to_string(),
        27 => "KDC_ERR_MUST_USE_USER2USER".to_string(),
        28 => "KDC_ERR_PATH_NOT_ACCEPTED".to_string(),
        29 => "KDC_ERR_SVC_UNAVAILABLE".to_string(),
        31 => "KRB_AP_ERR_BAD_INTEGRITY".to_string(),
        32 => "KRB_AP_ERR_TKT_EXPIRED".to_string(),
        33 => "KRB_AP_ERR_TKT_NYV".to_string(),
        34 => "KRB_AP_ERR_REPEAT".to_string(),
        35 => "KRB_AP_ERR_NOT_US".to_string(),
        36 => "KRB_AP_ERR_BADMATCH".to_string(),
        37 => "KRB_AP_ERR_SKEW".to_string(),
        38 => "KRB_AP_ERR_BADADDR".to_string(),
        39 => "KRB_AP_ERR_BADVERSION".to_string(),
        40 => "KRB_AP_ERR_MSG_TYPE".to_string(),
        41 => "KRB_AP_ERR_MODIFIED".to_string(),
        42 => "KRB_AP_ERR_BADORDER".to_string(),
        44 => "KRB_AP_ERR_BADKEYVER".to_string(),
        45 => "KRB_AP_ERR_NOKEY".to_string(),
        46 => "KRB_AP_ERR_MUT_FAIL".to_string(),
        47 => "KRB_AP_ERR_BADDIRECTION".to_string(),
        48 => "KRB_AP_ERR_METHOD".to_string(),
        49 => "KRB_AP_ERR_BADSEQ".to_string(),
        50 => "KRB_AP_ERR_INAPP_CKSUM".to_string(),
        51 => "KRB_AP_PATH_NOT_ACCEPTED".to_string(),
        52 => "KRB_ERR_RESPONSE_TOO_BIG".to_string(),
        60 => "KRB_ERR_GENERIC".to_string(),
        61 => "KRB_ERR_FIELD_TOOLONG".to_string(),
        62 => "KDC_ERROR_CLIENT_NOT_TRUSTED".to_string(),
        63 => "KDC_ERROR_KDC_NOT_TRUSTED".to_string(),
        64 => "KDC_ERROR_INVALID_SIG".to_string(),
        65 => "KDC_ERR_KEY_TOO_WEAK".to_string(),
        66 => "KDC_ERR_CERTIFICATE_MISMATCH".to_string(),
        67 => "KRB_AP_ERR_NO_TGT".to_string(),
        68 => "KDC_ERR_WRONG_REALM".to_string(),
        69 => "KRB_AP_ERR_USER_TO_USER_REQUIRED".to_string(),
        70 => "KDC_ERR_CANT_VERIFY_CERTIFICATE".to_string(),
        71 => "KDC_ERR_INVALID_CERTIFICATE".to_string(),
        72 => "KDC_ERR_REVOKED_CERTIFICATE".to_string(),
        73 => "KDC_ERR_REVOCATION_STATUS_UNKNOWN".to_string(),
        74 => "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE".to_string(),
        75 => "KDC_ERR_CLIENT_NAME_MISMATCH".to_string(),
        76 => "KDC_ERR_KDC_NAME_MISMATCH".to_string(),
        _ => "".to_string(),
    }
}
