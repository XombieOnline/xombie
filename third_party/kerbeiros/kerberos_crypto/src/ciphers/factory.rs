use crate::{Error, Result};
use crate::cryptography::AesSizes;
use kerberos_constants::etypes::{
    AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96, RC4_HMAC,
};
use crate::{KerberosCipher, AesCipher, Rc4Cipher};

/// Creates the appropiate cipher based on the encryption type specified
pub fn new_kerberos_cipher(etype: i32) -> Result<Box<dyn KerberosCipher>> {
    match etype {
        AES256_CTS_HMAC_SHA1_96 => {
            return Ok(Box::new(AesCipher::new(AesSizes::Aes256)));
        }
        AES128_CTS_HMAC_SHA1_96 => {
            return Ok(Box::new(AesCipher::new(AesSizes::Aes128)));
        }
        RC4_HMAC => {
            return Ok(Box::new(Rc4Cipher::new()));
        }
        _ => {
            return Err(Error::UnsupportedAlgorithm(etype))?;
        }
    }
}

