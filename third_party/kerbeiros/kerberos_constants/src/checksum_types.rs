//! Checksum types defined in RFC-4757

pub const RSA_MD5_DES: i32 = 8;
pub const RSA_MD4_DES: i32 = 4;
pub const HMAC_MD5: i32 = -138;
pub const HMAC_SHA1_DES3_KD: i32 = 12;
pub const HMAC_SHA1_96_AES128: i32 = 15;
pub const HMAC_SHA1_96_AES256: i32 = 16;

// RFC 8009
pub const HMAC_SHA256_128_AES128: i32 = 19;
pub const HMAC_SHA384_192_AES256: i32 = 20;
