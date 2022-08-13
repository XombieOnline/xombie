use crate::cryptography::{hmac_md5, rc4_decrypt, rc4_encrypt};
use crate::{Error, Result};


/// Encrypt plaintext by using the RC4 algorithm with HMAC-MD5
pub fn encrypt(
    key: &[u8],
    key_usage: i32,
    timestamp: &[u8],
    preamble: &[u8],
) -> Vec<u8> {
    let mut plaintext: Vec<u8> = Vec::new();
    plaintext.append(&mut preamble.to_vec());
    plaintext.append(&mut timestamp.to_vec());

    let ki = hmac_md5(key, &key_usage.to_le_bytes());
    let mut cksum = hmac_md5(&ki, &plaintext);
    let ke = hmac_md5(&ki, &cksum);

    let mut enc = rc4_encrypt(&ke, &plaintext);

    cksum.append(&mut enc);

    return cksum;
}

/// Decrypt ciphertext by using the RC4 algorithm with HMAC-MD5
pub fn decrypt(
    key: &[u8],
    key_usage: i32,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < 24 {
        return Err(Error::DecryptionError(
            "Ciphertext too short".to_string(),
        ))?;
    }

    let cksum = &ciphertext[0..16];
    let basic_ciphertext = &ciphertext[16..];
    let ki = hmac_md5(key, &key_usage.to_le_bytes());
    let ke = hmac_md5(&ki, &cksum);
    let plaintext = rc4_decrypt(&ke, &basic_ciphertext);

    let plaintext_cksum = hmac_md5(&ki, &plaintext);

    if cksum != &plaintext_cksum[..] {
        return Err(Error::DecryptionError(
            "Hmac integrity failure".to_string(),
        ))?;
    }

    return Ok(plaintext[8..].to_vec());
}
