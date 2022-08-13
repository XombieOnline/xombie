//! Exports the types of user keys available for this implementation.

use crate::utils::random_bytes;
use crate::{Error, Result};
use crate::{AES128_KEY_SIZE, AES256_KEY_SIZE, RC4_KEY_SIZE};
use kerberos_constants::etypes::{
    AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96, RC4_HMAC,
};
use std::result;

/// Encapsules the possible keys used by this Kerberos implementation.
/// Each key can be used by a different cryptographic algorithm.
#[derive(Debug, PartialEq, Clone)]
pub enum Key {
    /// The secret of the user. This is the most versatile key,
    /// since can it can be use to derive the rest of the keys,
    /// and therefore, being used by any cryptographic algorithm.
    Secret(String),

    /// RC4 key used by RC4-HMAC algorithm.
    /// In Windows, this is the NTLM hash of the user password.
    RC4Key([u8; RC4_KEY_SIZE]),

    /// AES key used by AES128-CTS-HMAC-SHA1-96 algorithm.
    AES128Key([u8; AES128_KEY_SIZE]),

    /// AES key used by AES256-CTS-HMAC-SHA1-96 algorithm.
    AES256Key([u8; AES256_KEY_SIZE]),
}

impl Key {
    /// Generates a random key of the given etype
    /// # Error
    /// Returns error if the etype is not supported
    pub fn random(etype: i32) -> Result<Self> {
        match etype {
            RC4_HMAC => Ok(Self::RC4Key(from_slice_to_rc4_key(&random_bytes(
                RC4_KEY_SIZE,
            )))),
            AES128_CTS_HMAC_SHA1_96 => Ok(Self::AES128Key(
                from_slice_to_aes128_key(&random_bytes(AES128_KEY_SIZE)),
            )),
            AES256_CTS_HMAC_SHA1_96 => Ok(Self::AES256Key(
                from_slice_to_aes256_key(&random_bytes(AES256_KEY_SIZE)),
            )),
            _ => Err(Error::UnsupportedAlgorithm(etype)),
        }
    }

    /// Return the etypes associated with the type of key.
    ///
    /// # Examples
    /// ```
    /// use kerberos_crypto::*;
    /// use kerberos_constants::etypes::*;
    ///
    /// assert_eq!(
    ///     vec![AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC],
    ///     Key::Secret("".to_string()).etypes()
    /// );
    /// assert_eq!(vec![RC4_HMAC], Key::RC4Key([0; RC4_KEY_SIZE]).etypes());
    /// assert_eq!(
    ///     vec![AES128_CTS_HMAC_SHA1_96],
    ///     Key::AES128Key([0; AES128_KEY_SIZE]).etypes()
    /// );
    /// assert_eq!(
    ///     vec![AES256_CTS_HMAC_SHA1_96],
    ///     Key::AES256Key([0; AES256_KEY_SIZE]).etypes()
    /// );
    /// ```
    pub fn etypes(&self) -> Vec<i32> {
        match self {
            Key::Secret(_) => {
                vec![AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC]
            }
            Key::RC4Key(_) => vec![RC4_HMAC],
            Key::AES128Key(_) => vec![AES128_CTS_HMAC_SHA1_96],
            Key::AES256Key(_) => vec![AES256_CTS_HMAC_SHA1_96],
        }
    }

    /// Retrieve the key as an array of bytes.
    ///
    /// # Examples
    /// ```
    /// use kerberos_crypto::*;
    ///
    /// assert_eq!(&[0x73, 0x65, 0x63, 0x72, 0x65, 0x74], Key::Secret("secret".to_string()).as_bytes());
    /// assert_eq!(&[0; RC4_KEY_SIZE], Key::RC4Key([0; RC4_KEY_SIZE]).as_bytes());
    /// assert_eq!(&[0; AES128_KEY_SIZE], Key::AES128Key([0; AES128_KEY_SIZE]).as_bytes());
    /// assert_eq!(&[0; AES256_KEY_SIZE], Key::AES256Key([0; AES256_KEY_SIZE]).as_bytes());
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Key::Secret(ref secret) => secret.as_bytes(),
            Key::RC4Key(ref rc4key) => rc4key,
            Key::AES128Key(ref aeskey) => aeskey,
            Key::AES256Key(ref aeskey) => aeskey,
        }
    }

    /// Get a RC4 key from a hexdump.
    /// # Example
    ///
    /// ```
    /// use kerberos_crypto::Key;
    /// assert_eq!(
    ///     Key::RC4Key([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
    ///     Key::from_rc4_key_string("0123456789ABCDEF0123456789abcdef").unwrap()
    /// );
    /// ```
    /// # Errors
    /// An error if raised if the argument string has any non hexadecimal character or size is different from 32.
    ///
    pub fn from_rc4_key_string(hex_str: &str) -> Result<Self> {
        let ntlm =
            Self::check_size_and_convert_in_byte_array(hex_str, RC4_KEY_SIZE)?;

        let mut key = [0; RC4_KEY_SIZE];
        key.copy_from_slice(&ntlm[0..RC4_KEY_SIZE]);

        return Ok(Key::RC4Key(key));
    }

    /// Get a AES-128 key from a hexdump.
    /// # Example
    ///
    /// ```
    /// use kerberos_crypto::Key;
    /// assert_eq!(
    ///     Key::AES128Key([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
    ///     Key::from_aes_128_key_string("0123456789ABCDEF0123456789abcdef").unwrap()
    /// );
    /// ```
    /// # Errors
    /// An error if raised if the argument string has any non hexadecimal character or size is different from 32.
    ///
    pub fn from_aes_128_key_string(hex_str: &str) -> Result<Self> {
        let ntlm = Self::check_size_and_convert_in_byte_array(
            hex_str,
            AES128_KEY_SIZE,
        )?;

        let mut key = [0; AES128_KEY_SIZE];
        key.copy_from_slice(&ntlm[0..AES128_KEY_SIZE]);

        return Ok(Key::AES128Key(key));
    }

    /// Get a AES-256 key from a hexdump.
    /// # Example
    ///
    /// ```
    /// use kerberos_crypto::Key;
    /// assert_eq!(
    ///     Key::AES256Key([
    ///         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ///         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    ///     ]),
    ///     Key::from_aes_256_key_string("0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef").unwrap()
    /// );
    /// ```
    /// # Errors
    /// An error if raised if the argument string has any non hexadecimal character or size is different from 64.
    ///
    pub fn from_aes_256_key_string(hex_str: &str) -> Result<Self> {
        let ntlm = Self::check_size_and_convert_in_byte_array(
            hex_str,
            AES256_KEY_SIZE,
        )?;

        let mut key = [0; AES256_KEY_SIZE];
        key.copy_from_slice(&ntlm[0..AES256_KEY_SIZE]);

        return Ok(Key::AES256Key(key));
    }

    fn check_size_and_convert_in_byte_array(
        hex_str: &str,
        size: usize,
    ) -> Result<Vec<u8>> {
        if hex_str.len() != size * 2 {
            return Err(Error::InvalidKeyLength(size * 2))?;
        }

        return Ok(Self::convert_hex_string_into_byte_array(hex_str)
            .map_err(|_| Error::InvalidKeyCharset)?);
    }

    fn convert_hex_string_into_byte_array(
        hex_str: &str,
    ) -> result::Result<Vec<u8>, std::num::ParseIntError> {
        let key_size = hex_str.len() / 2;
        let mut bytes = Vec::with_capacity(key_size);
        for i in 0..key_size {
            let str_index = i * 2;
            bytes.push(u8::from_str_radix(
                &hex_str[str_index..str_index + 2],
                16,
            )?);
        }

        return Ok(bytes);
    }
}

fn from_slice_to_rc4_key(bytes: &[u8]) -> [u8; RC4_KEY_SIZE] {
    let mut array = [0; RC4_KEY_SIZE];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

fn from_slice_to_aes128_key(bytes: &[u8]) -> [u8; AES128_KEY_SIZE] {
    let mut array = [0; AES128_KEY_SIZE];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

fn from_slice_to_aes256_key(bytes: &[u8]) -> [u8; AES256_KEY_SIZE] {
    let mut array = [0; AES256_KEY_SIZE];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hex_string_to_rc4_key() {
        assert_eq!(
            Key::RC4Key([0; RC4_KEY_SIZE]),
            Key::from_rc4_key_string("00000000000000000000000000000000")
                .unwrap()
        );
        assert_eq!(
            Key::RC4Key([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
                0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
            ]),
            Key::from_rc4_key_string("0123456789ABCDEF0123456789abcdef")
                .unwrap()
        );
    }

    #[should_panic(expected = "InvalidKeyLength(32)")]
    #[test]
    fn invalid_length_hex_string_to_rc4_key() {
        Key::from_rc4_key_string("0").unwrap();
    }

    #[should_panic(expected = "InvalidKeyCharset")]
    #[test]
    fn invalid_chars_hex_string_to_rc4_key() {
        Key::from_rc4_key_string("ERROR_0123456789ABCDEF0123456789").unwrap();
    }

    #[test]
    fn hex_string_to_aes_128_key() {
        assert_eq!(
            Key::AES128Key([0; AES128_KEY_SIZE]),
            Key::from_aes_128_key_string("00000000000000000000000000000000")
                .unwrap()
        );
        assert_eq!(
            Key::AES128Key([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
                0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
            ]),
            Key::from_aes_128_key_string("0123456789ABCDEF0123456789abcdef")
                .unwrap()
        );
    }

    #[should_panic(expected = "InvalidKeyLength(32)")]
    #[test]
    fn invalid_length_hex_string_to_aes_128_key() {
        Key::from_aes_128_key_string("0").unwrap();
    }

    #[should_panic(expected = "InvalidKeyCharset")]
    #[test]
    fn invalid_chars_hex_string_to_aes_128_key() {
        Key::from_aes_128_key_string("ERROR_0123456789ABCDEF0123456789")
            .unwrap();
    }

    #[test]
    fn hex_string_to_aes_256_key() {
        assert_eq!(
            Key::AES256Key([0; AES256_KEY_SIZE]),
            Key::from_aes_256_key_string(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
            .unwrap()
        );
        assert_eq!(
            Key::AES256Key([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab, 0xcd, 0xef
            ]),
            Key::from_aes_256_key_string(
                "0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef"
            )
            .unwrap()
        );
    }

    #[should_panic(expected = "InvalidKeyLength(64)")]
    #[test]
    fn invalid_length_hex_string_to_aes_256_key() {
        Key::from_aes_256_key_string("0").unwrap();
    }

    #[should_panic(expected = "InvalidKeyCharset")]
    #[test]
    fn invalid_chars_hex_string_to_aes_256_key() {
        Key::from_aes_256_key_string(
            "ERROR_0123456789ABCDEF0123456789ERROR_0123456789ABCDEF0123456789",
        )
        .unwrap();
    }
}
