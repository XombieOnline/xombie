//! Useful public functions

use kerberos_constants::etypes::{
    AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96, RC4_HMAC,
};


/// Helper to check is an encryption type is supported by this library
pub fn is_supported_etype(etype: i32) -> bool {
    return supported_etypes().contains(&etype);
}

/// Returns a vector with the etypes of the supported algorithms
/// by this library
pub fn supported_etypes() -> Vec<i32> {
    vec![
        AES256_CTS_HMAC_SHA1_96,
        AES128_CTS_HMAC_SHA1_96,
        RC4_HMAC
    ]
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::etypes::*;

    #[test]
    fn supported_etypes() {
        assert_eq!(true, is_supported_etype(AES256_CTS_HMAC_SHA1_96));
        assert_eq!(true, is_supported_etype(AES128_CTS_HMAC_SHA1_96));
        assert_eq!(true, is_supported_etype(RC4_HMAC));
        assert_eq!(false, is_supported_etype(NO_ENCRYPTION));
        assert_eq!(false, is_supported_etype(RC4_HMAC_EXP));
        assert_eq!(false, is_supported_etype(DES_CBC_MD5));
        assert_eq!(false, is_supported_etype(DES_CBC_CRC));
        assert_eq!(false, is_supported_etype(RC4_HMAC_OLD_EXP));
        assert_eq!(
            false,
            is_supported_etype(
                AES256_CTS_HMAC_SHA1_96 | AES128_CTS_HMAC_SHA1_96
            )
        );
    }
}
