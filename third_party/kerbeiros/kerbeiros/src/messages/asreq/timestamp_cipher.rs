use kerberos_asn1::{PaEncTsEnc, Asn1Object};
use kerberos_crypto::Key;
use crate::{Error, Result};
use ascii::AsciiString;
use chrono::Utc;
use kerberos_constants::etypes::{
    AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96, RC4_HMAC,
};
use kerberos_constants::key_usages::KEY_USAGE_AS_REQ_TIMESTAMP;
use kerberos_crypto::new_kerberos_cipher;

pub struct AsReqTimestampCipher<'a> {
    realm: &'a AsciiString,
    username: &'a AsciiString,
    user_key: &'a Key,
    etypes: &'a Vec<i32>,
    raw_timestamp: Vec<u8>,
}

impl<'a> AsReqTimestampCipher<'a> {
    pub fn build_encrypted_timestamp(
        realm: &'a AsciiString,
        username: &'a AsciiString,
        user_key: &'a Key,
        etypes: &'a Vec<i32>,
    ) -> Result<(i32, Vec<u8>)> {
        let timestamp_builder = Self::new(realm, username, user_key, etypes);
        return timestamp_builder.produce_encrypted_timestamp();
    }

    fn new(
        realm: &'a AsciiString,
        username: &'a AsciiString,
        user_key: &'a Key,
        etypes: &'a Vec<i32>,
    ) -> Self {
        return Self {
            realm,
            username,
            user_key,
            etypes,
            raw_timestamp: Self::produce_raw_timestamp(),
        };
    }

    fn produce_raw_timestamp() -> Vec<u8> {
        let timestamp = PaEncTsEnc::from(Utc::now());
        return timestamp.build();
    }

    fn produce_encrypted_timestamp(&self) -> Result<(i32, Vec<u8>)> {
        match self.user_key {
            Key::Secret(password) => {
                return self
                    .encrypt_timestamp_with_best_cipher_and_password(password);
            }
            Key::RC4Key(rc4_key) => {
                return self
                    .encrypt_timestamp_with_cipher_and_key(RC4_HMAC, rc4_key);
            }
            Key::AES128Key(aes_key_128) => {
                return self.encrypt_timestamp_with_cipher_and_key(
                    AES128_CTS_HMAC_SHA1_96,
                    aes_key_128,
                );
            }
            Key::AES256Key(aes_key_256) => {
                return self.encrypt_timestamp_with_cipher_and_key(
                    AES256_CTS_HMAC_SHA1_96,
                    aes_key_256,
                );
            }
        }
    }

    fn encrypt_timestamp_with_best_cipher_and_password(
        &self,
        password: &str,
    ) -> Result<(i32, Vec<u8>)> {
        let etype;
        let salt;

        if self.etypes.contains(&AES256_CTS_HMAC_SHA1_96) {
            etype = AES256_CTS_HMAC_SHA1_96;
            salt = self.calculate_aes_salt();
        } else if self.etypes.contains(&AES128_CTS_HMAC_SHA1_96) {
            etype = AES128_CTS_HMAC_SHA1_96;
            salt = self.calculate_aes_salt();
        } else if self.etypes.contains(&RC4_HMAC) {
            etype = RC4_HMAC;
            salt = Vec::new();
        } else {
            return Err(Error::NoProvidedSupportedCipherAlgorithm)?;
        }

        return self.encrypt_timestamp_with_cipher_and_password(
            etype, password, &salt,
        );
    }

    fn encrypt_timestamp_with_cipher_and_key(
        &self,
        etype: i32,
        key: &[u8],
    ) -> Result<(i32, Vec<u8>)> {
        let cipher = new_kerberos_cipher(etype)?;
        return Ok((
            etype,
            cipher.encrypt(
                key,
                KEY_USAGE_AS_REQ_TIMESTAMP,
                &self.raw_timestamp,
            ),
        ));
    }

    fn encrypt_timestamp_with_cipher_and_password(
        &self,
        etype: i32,
        password: &str,
        salt: &[u8],
    ) -> Result<(i32, Vec<u8>)> {
        let cipher = new_kerberos_cipher(etype)?;
        return Ok((
            etype,
            cipher.generate_key_from_string_and_encrypt(
                password,
                salt,
                KEY_USAGE_AS_REQ_TIMESTAMP,
                &self.raw_timestamp,
            ),
        ));
    }

    fn calculate_aes_salt(&self) -> Vec<u8> {
        let mut salt = self.realm.to_string().to_uppercase();
        let mut lowercase_username = self.username.to_string().to_lowercase();

        if lowercase_username.ends_with("$") {
            salt.push_str("host");
            lowercase_username.pop();
        }
        salt.push_str(&lowercase_username);

        return salt.as_bytes().to_vec();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn produce_encrypted_timestamp_with_rc4_key() {
        let etypes = vec![RC4_HMAC];
        let key = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59,
            0xd7, 0xe0, 0xc0, 0x89, 0xc0,
        ];

        let (result_etype, timestamp) =
            AsReqTimestampCipher::build_encrypted_timestamp(
                &AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
                &AsciiString::from_ascii("Mickey").unwrap(),
                &Key::RC4Key(key.clone()),
                &etypes,
            )
            .unwrap();

        assert_eq!(RC4_HMAC, result_etype);
        new_kerberos_cipher(RC4_HMAC)
            .unwrap()
            .decrypt(&key, KEY_USAGE_AS_REQ_TIMESTAMP, &timestamp)
            .unwrap();
    }

    #[test]
    fn produce_encrypted_timestamp_with_aes128_key() {
        let etypes = vec![AES128_CTS_HMAC_SHA1_96];
        let key = [
            0x61, 0x7f, 0x72, 0xfd, 0xbc, 0x85, 0x1c, 0x45, 0x9a, 0x1c, 0x39,
            0xbf, 0x83, 0x23, 0x56, 0x09,
        ];

        let (result_etype, timestamp) =
            AsReqTimestampCipher::build_encrypted_timestamp(
                &AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
                &AsciiString::from_ascii("Mickey").unwrap(),
                &Key::AES128Key(key.clone()),
                &etypes,
            )
            .unwrap();

        assert_eq!(AES128_CTS_HMAC_SHA1_96, result_etype);
        new_kerberos_cipher(AES128_CTS_HMAC_SHA1_96)
            .unwrap()
            .decrypt(&key, KEY_USAGE_AS_REQ_TIMESTAMP, &timestamp)
            .unwrap();
    }

    #[test]
    fn produce_encrypted_timestamp_with_aes256_key() {
        let etypes = vec![AES256_CTS_HMAC_SHA1_96];
        let key = [
            0xd3, 0x30, 0x1f, 0x0f, 0x25, 0x39, 0xcc, 0x40, 0x26, 0xa5, 0x69,
            0xf8, 0xb7, 0xc3, 0x67, 0x15, 0xc8, 0xda, 0xef, 0x10, 0x9f, 0xa3,
            0xd8, 0xb2, 0xe1, 0x46, 0x16, 0xaa, 0xca, 0xb5, 0x49, 0xfd,
        ];

        let (result_etype, timestamp) =
            AsReqTimestampCipher::build_encrypted_timestamp(
                &AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
                &AsciiString::from_ascii("Mickey").unwrap(),
                &Key::AES256Key(key.clone()),
                &etypes,
            )
            .unwrap();

        assert_eq!(AES256_CTS_HMAC_SHA1_96, result_etype);
        new_kerberos_cipher(AES256_CTS_HMAC_SHA1_96)
            .unwrap()
            .decrypt(&key, KEY_USAGE_AS_REQ_TIMESTAMP, &timestamp)
            .unwrap();
    }

    #[test]
    fn produce_encrypted_timestamp_with_rc4_key_without_specify_any_cipher() {
        let etypes = vec![];
        let key = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59,
            0xd7, 0xe0, 0xc0, 0x89, 0xc0,
        ];

        let (result_etype, timestamp) =
            AsReqTimestampCipher::build_encrypted_timestamp(
                &AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
                &AsciiString::from_ascii("Mickey").unwrap(),
                &Key::RC4Key(key.clone()),
                &etypes,
            )
            .unwrap();

        assert_eq!(RC4_HMAC, result_etype);
        new_kerberos_cipher(RC4_HMAC)
            .unwrap()
            .decrypt(&key, KEY_USAGE_AS_REQ_TIMESTAMP, &timestamp)
            .unwrap();
    }

    #[test]
    fn produce_encrypted_timestamp_with_aes128_key_without_specify_any_cipher()
    {
        let etypes = vec![];
        let key = [
            0x61, 0x7f, 0x72, 0xfd, 0xbc, 0x85, 0x1c, 0x45, 0x9a, 0x1c, 0x39,
            0xbf, 0x83, 0x23, 0x56, 0x09,
        ];

        let (result_etype, timestamp) =
            AsReqTimestampCipher::build_encrypted_timestamp(
                &AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
                &AsciiString::from_ascii("Mickey").unwrap(),
                &Key::AES128Key(key.clone()),
                &etypes,
            )
            .unwrap();

        assert_eq!(AES128_CTS_HMAC_SHA1_96, result_etype);
        new_kerberos_cipher(AES128_CTS_HMAC_SHA1_96)
            .unwrap()
            .decrypt(&key, KEY_USAGE_AS_REQ_TIMESTAMP, &timestamp)
            .unwrap();
    }

    #[test]
    fn produce_encrypted_timestamp_with_aes256_key_without_specify_any_cipher()
    {
        let etypes = vec![];
        let key = [
            0xd3, 0x30, 0x1f, 0x0f, 0x25, 0x39, 0xcc, 0x40, 0x26, 0xa5, 0x69,
            0xf8, 0xb7, 0xc3, 0x67, 0x15, 0xc8, 0xda, 0xef, 0x10, 0x9f, 0xa3,
            0xd8, 0xb2, 0xe1, 0x46, 0x16, 0xaa, 0xca, 0xb5, 0x49, 0xfd,
        ];

        let (result_etype, timestamp) =
            AsReqTimestampCipher::build_encrypted_timestamp(
                &AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
                &AsciiString::from_ascii("Mickey").unwrap(),
                &Key::AES256Key(key.clone()),
                &etypes,
            )
            .unwrap();

        assert_eq!(AES256_CTS_HMAC_SHA1_96, result_etype);
        new_kerberos_cipher(AES256_CTS_HMAC_SHA1_96)
            .unwrap()
            .decrypt(&key, KEY_USAGE_AS_REQ_TIMESTAMP, &timestamp)
            .unwrap();
    }

    #[should_panic(expected = "NoProvidedSupportedCipherAlgorithm")]
    #[test]
    fn error_using_password_without_any_cipher_algorithm() {
        let etypes = Vec::new();
        AsReqTimestampCipher::build_encrypted_timestamp(
            &AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
            &AsciiString::from_ascii("Mickey").unwrap(),
            &Key::Secret("password".to_string()),
            &etypes,
        )
        .unwrap();
    }

    #[test]
    fn produce_encrypted_timestamp_with_password_setting_aes256_as_best_cipher()
    {
        let etypes =
            vec![AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC];
        let password = "password";

        let (result_etype, timestamp) =
            AsReqTimestampCipher::build_encrypted_timestamp(
                &AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
                &AsciiString::from_ascii("Mickey").unwrap(),
                &Key::Secret(password.to_string()),
                &etypes,
            )
            .unwrap();

        assert_eq!(AES256_CTS_HMAC_SHA1_96, result_etype);
        new_kerberos_cipher(AES256_CTS_HMAC_SHA1_96)
            .unwrap()
            .generate_key_from_string_and_decrypt(
                &password,
                &"KINGDOM.HEARTSmickey".as_bytes(),
                KEY_USAGE_AS_REQ_TIMESTAMP,
                &timestamp,
            )
            .unwrap();
    }

    #[test]
    fn produce_encrypted_timestamp_with_password_setting_aes128_as_best_cipher()
    {
        let etypes = vec![AES128_CTS_HMAC_SHA1_96, RC4_HMAC];
        let password = "password";

        let (result_etype, timestamp) =
            AsReqTimestampCipher::build_encrypted_timestamp(
                &AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
                &AsciiString::from_ascii("Mickey").unwrap(),
                &Key::Secret(password.to_string()),
                &etypes,
            )
            .unwrap();

        assert_eq!(AES128_CTS_HMAC_SHA1_96, result_etype);
        new_kerberos_cipher(AES128_CTS_HMAC_SHA1_96)
            .unwrap()
            .generate_key_from_string_and_decrypt(
                &password,
                &"KINGDOM.HEARTSmickey".as_bytes(),
                KEY_USAGE_AS_REQ_TIMESTAMP,
                &timestamp,
            )
            .unwrap();
    }

    #[test]
    fn produce_encrypted_timestamp_with_password_setting_rc4_as_best_cipher() {
        let etypes = vec![RC4_HMAC];
        let password = "password";

        let (result_etype, timestamp) =
            AsReqTimestampCipher::build_encrypted_timestamp(
                &AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
                &AsciiString::from_ascii("Mickey").unwrap(),
                &Key::Secret(password.to_string()),
                &etypes,
            )
            .unwrap();

        assert_eq!(RC4_HMAC, result_etype);
        new_kerberos_cipher(RC4_HMAC)
            .unwrap()
            .generate_key_from_string_and_decrypt(
                &password,
                &"".as_bytes(),
                KEY_USAGE_AS_REQ_TIMESTAMP,
                &timestamp,
            )
            .unwrap();
    }
}
