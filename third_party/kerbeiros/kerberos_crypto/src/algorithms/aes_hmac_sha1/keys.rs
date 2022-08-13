use crate::cryptography::{pbkdf2_sha1, AesSizes, dk};

/// Derive the AES key used to encrypt/decrypt from the user secret (password)
pub fn generate_key(
    passphrase: &[u8],
    salt: &[u8],
    aes_sizes: &AesSizes,
) -> Vec<u8> {
    let key = pbkdf2_sha1(passphrase, salt, aes_sizes.seed_size());
    return dk(&key, "kerberos".as_bytes(), aes_sizes);
}

/// Derive the AES key used to encrypt/decrypt from the string representation of the user secret (password)
pub fn generate_key_from_string(
    string: &str,
    salt: &[u8],
    aes_sizes: &AesSizes,
) -> Vec<u8> {
    return generate_key(string.as_bytes(), salt, aes_sizes)
}

#[cfg(test)]
mod test {
    use super::*;

    fn generate_aes_128_key(passphrase: &[u8], salt: &[u8]) -> Vec<u8> {
        return generate_key(passphrase, salt, &AesSizes::Aes128);
    }

    fn generate_aes_256_key(passphrase: &[u8], salt: &[u8]) -> Vec<u8> {
        return generate_key(passphrase, salt, &AesSizes::Aes256);
    }

    #[test]
    fn test_generate_aes_128_key() {
        assert_eq!(
            vec![
                0x61, 0x7f, 0x72, 0xfd, 0xbc, 0x85, 0x1c, 0x45, 0x9a, 0x1c,
                0x39, 0xbf, 0x83, 0x23, 0x56, 0x09
            ],
            generate_aes_128_key(
                "Minnie1234".as_bytes(),
                "KINGDOM.HEARTSmickey".as_bytes()
            )
        );

        assert_eq!(
            vec![
                0x19, 0xa9, 0xb7, 0xc0, 0x87, 0xf8, 0xfd, 0x3d, 0xf5, 0x94,
                0xaf, 0xd2, 0xc7, 0xf6, 0x64, 0x73
            ],
            generate_aes_128_key(
                "Sora1234".as_bytes(),
                "KINGDOM.HEARTSroxas".as_bytes()
            )
        );

        assert_eq!(
            vec![
                0x83, 0x91, 0x03, 0x34, 0x5b, 0x8b, 0x01, 0x69, 0xb6, 0xff,
                0x47, 0xe6, 0x14, 0xe6, 0xce, 0xec
            ],
            generate_aes_128_key(
                "Kairi1234".as_bytes(),
                "KINGDOM.HEARTSnamine".as_bytes()
            )
        );

        assert_eq!(
            vec![
                0x66, 0x6b, 0x33, 0x75, 0x4d, 0x8b, 0xdd, 0x0e, 0xd2, 0x58,
                0x99, 0x93, 0xcb, 0xcc, 0x77, 0x8e
            ],
            generate_aes_128_key(
                "Roxas1234".as_bytes(),
                "KINGDOM.HEARTSxion".as_bytes()
            )
        );
    }

    #[test]
    fn test_generate_aes_256_key() {
        assert_eq!(
            vec![
                0xd3, 0x30, 0x1f, 0x0f, 0x25, 0x39, 0xcc, 0x40, 0x26, 0xa5,
                0x69, 0xf8, 0xb7, 0xc3, 0x67, 0x15, 0xc8, 0xda, 0xef, 0x10,
                0x9f, 0xa3, 0xd8, 0xb2, 0xe1, 0x46, 0x16, 0xaa, 0xca, 0xb5,
                0x49, 0xfd
            ],
            generate_aes_256_key(
                "Minnie1234".as_bytes(),
                "KINGDOM.HEARTSmickey".as_bytes()
            )
        );

        assert_eq!(
            vec![
                0x99, 0xc8, 0x9e, 0xd5, 0x12, 0x19, 0x84, 0xc8, 0xe4, 0x12,
                0xc1, 0xa7, 0xc1, 0x34, 0x69, 0x0f, 0x61, 0xc9, 0x55, 0x48,
                0x38, 0x8b, 0xba, 0x20, 0x8f, 0xd9, 0xd9, 0x98, 0x6c, 0x8f,
                0x77, 0xd6
            ],
            generate_aes_256_key(
                "Sora1234".as_bytes(),
                "KINGDOM.HEARTSroxas".as_bytes()
            )
        );

        assert_eq!(
            vec![
                0x86, 0x95, 0xf8, 0x2e, 0x92, 0x0e, 0x0a, 0xce, 0x42, 0x9b,
                0x8d, 0x9e, 0xf6, 0x19, 0x67, 0x0d, 0x03, 0x67, 0x43, 0x0c,
                0x12, 0xb3, 0x23, 0x3f, 0x32, 0xc5, 0xc8, 0x9f, 0xb7, 0xd6,
                0x04, 0xff
            ],
            generate_aes_256_key(
                "Kairi1234".as_bytes(),
                "KINGDOM.HEARTSnamine".as_bytes()
            )
        );

        assert_eq!(
            vec![
                0xd6, 0x52, 0xf8, 0x5d, 0x86, 0x5d, 0x92, 0xe3, 0x47, 0xf6,
                0xa5, 0x6b, 0x63, 0x5d, 0x31, 0x02, 0x3b, 0x92, 0x65, 0x1a,
                0x00, 0x2c, 0x05, 0x9d, 0x8d, 0xb8, 0xee, 0x2a, 0x06, 0xd2,
                0x65, 0x0f
            ],
            generate_aes_256_key(
                "Roxas1234".as_bytes(),
                "KINGDOM.HEARTSxion".as_bytes()
            )
        );
    }


    #[test]
    fn test_generate_key_from_string() {
        assert_eq!(
            vec![
                0x61, 0x7f, 0x72, 0xfd, 0xbc, 0x85, 0x1c, 0x45, 0x9a, 0x1c,
                0x39, 0xbf, 0x83, 0x23, 0x56, 0x09
            ],
            generate_key_from_string(
                "Minnie1234",
                "KINGDOM.HEARTSmickey".as_bytes(),
                &AesSizes::Aes128
            )
        );

        assert_eq!(
            vec![
                0xd3, 0x30, 0x1f, 0x0f, 0x25, 0x39, 0xcc, 0x40, 0x26, 0xa5,
                0x69, 0xf8, 0xb7, 0xc3, 0x67, 0x15, 0xc8, 0xda, 0xef, 0x10,
                0x9f, 0xa3, 0xd8, 0xb2, 0xe1, 0x46, 0x16, 0xaa, 0xca, 0xb5,
                0x49, 0xfd
            ],
            generate_key_from_string(
                "Minnie1234",
                "KINGDOM.HEARTSmickey".as_bytes(),
                &AesSizes::Aes256
            )
        );
    }
}
