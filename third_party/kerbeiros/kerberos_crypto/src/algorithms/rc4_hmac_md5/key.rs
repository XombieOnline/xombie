use crate::cryptography::md4;
use crate::utils::string_unicode_bytes;

/// Derive the RC4 key used to encrypt/decrypt from the
/// user secret (password)
pub fn generate_key(secret: &[u8]) -> Vec<u8> {
    return md4(secret);
}

/// Derive the RC4 key used to encrypt/decrypt from the string
/// representation of the user secret (password)
pub fn generate_key_from_string(string: &str) -> Vec<u8> {
    let raw_key = string_unicode_bytes(string);
    return generate_key(&raw_key);
}

#[cfg(test)]
mod test {
    use super::*;

    fn rc4_key_gen(password: &str) -> Vec<u8> {
        return generate_key_from_string(password);
    }

    #[test]
    fn generate_rc4_key() {
        assert_eq!(
            vec![
                0x20, 0x9c, 0x61, 0x74, 0xda, 0x49, 0x0c, 0xae, 0xb4, 0x22,
                0xf3, 0xfa, 0x5a, 0x7a, 0xe6, 0x34
            ],
            rc4_key_gen("admin")
        );
        assert_eq!(
            vec![
                0x0c, 0xb6, 0x94, 0x88, 0x05, 0xf7, 0x97, 0xbf, 0x2a, 0x82,
                0x80, 0x79, 0x73, 0xb8, 0x95, 0x37
            ],
            rc4_key_gen("test")
        );
        assert_eq!(
            vec![
                0x2f, 0xd6, 0xbd, 0xe7, 0xdb, 0x06, 0x81, 0x88, 0x74, 0x98,
                0x91, 0x4c, 0xb2, 0xd2, 0x01, 0xef
            ],
            rc4_key_gen("1337")
        );
        assert_eq!(
            vec![
                0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c,
                0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
            ],
            rc4_key_gen("")
        );
        assert_eq!(
            vec![
                0x25, 0x97, 0x45, 0xcb, 0x12, 0x3a, 0x52, 0xaa, 0x2e, 0x69,
                0x3a, 0xaa, 0xcc, 0xa2, 0xdb, 0x52
            ],
            rc4_key_gen("12345678")
        );
        assert_eq!(
            vec![
                0xc2, 0x2b, 0x31, 0x5c, 0x04, 0x0a, 0xe6, 0xe0, 0xef, 0xee,
                0x35, 0x18, 0xd8, 0x30, 0x36, 0x2b
            ],
            rc4_key_gen("123456789")
        );
    }
}
