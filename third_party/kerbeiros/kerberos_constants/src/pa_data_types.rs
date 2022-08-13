//! Preauthentication data types used by Kerberos protocol.
//!
//! # References
//! * RFC 4210, Section 7.5.2.
//! * [MS-KILE], Section 3.1.5.1.

pub const PA_TGS_REQ: i32 = 1;
pub const PA_ENC_TIMESTAMP: i32 = 2;
pub const PA_PW_SALT: i32 = 3;
pub const PA_ENC_UNIX_TIME: i32 = 5;
pub const PA_SANDIA_SECUREID: i32 = 6;
pub const PA_SESAME: i32 = 7;
pub const PA_OSF_DCE: i32 = 8;
pub const PA_CYBERSAFE_SECUREID: i32 = 9;
pub const PA_AFS3_SALT: i32 = 10;
pub const PA_ETYPE_INFO: i32 = 11;
pub const PA_SAM_CHALLENGE: i32 = 12;
pub const PA_SAM_RESPONSE: i32 = 13;
pub const PA_PK_AS_REQ_OLD: i32 = 14;
pub const PA_PK_AS_REP_OLD: i32 = 15;
pub const PA_PK_AS_REQ: i32 = 16;
pub const PA_PK_AS_REP: i32 = 17;
pub const PA_ETYPE_INFO2: i32 = 19;
pub const PA_SVR_REFERRAL_INFO: i32 = 20;
pub const PA_USE_SPECIFIED_KVNO: i32 = 20;
pub const PA_SAM_REDIRECT: i32 = 21;
pub const PA_GET_FROM_TYPED_DATA: i32 = 22;
pub const TD_PADATA: i32 = 22;
pub const PA_SAM_ETYPE_INFO: i32 = 23;
pub const PA_ALT_PRINC: i32 = 24;
pub const PA_SAM_CHALLENGE2: i32 = 30;
pub const PA_SAM_RESPONSE2: i32 = 31;
pub const PA_EXTRA_TGT: i32 = 41;
pub const TD_PKINIT_CMS_CERTIFICATES: i32 = 101;
pub const TD_KRB_PRINCIPAL: i32 = 102;
pub const TD_KRB_REALM: i32 = 103;
pub const TD_TRUSTED_CERTIFIERS: i32 = 104;
pub const TD_CERTIFICATE_INDEX: i32 = 105;
pub const TD_APP_DEFINED_ERROR: i32 = 106;
pub const TD_REQ_NONCE: i32 = 107;
pub const TD_REQ_SEQ: i32 = 108;
pub const PA_PAC_REQUEST: i32 = 128;
pub const PA_FOR_USER: i32 = 129;
pub const PA_FX_COOKIE: i32 = 133;
pub const PA_FX_FAST: i32 = 136;
pub const PA_FX_ERROR: i32 = 137;
pub const PA_ENCRYPTED_CHALLENGE: i32 = 138;
pub const KERB_KEY_LIST_REQ: i32 = 161;
pub const KERB_KEY_LIST_REP: i32 = 162;
pub const PA_SUPPORTED_ENCTYPES: i32 = 165;
pub const PA_PAC_OPTIONS: i32 = 167;

