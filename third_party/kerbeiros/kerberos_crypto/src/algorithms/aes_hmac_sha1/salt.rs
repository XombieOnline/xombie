/// Creates the AES salt from the realm and the client name
pub fn generate_salt(realm: &str, client_name: &str) -> Vec<u8> {
    let mut salt = realm.to_uppercase();
    let mut lowercase_username = client_name.to_lowercase();

    if lowercase_username.ends_with("$") {
        // client name = "host<client_name>.lower.domain.com"
        salt.push_str("host");
        lowercase_username.pop();
        salt.push_str(&lowercase_username);
        salt.push('.');
        salt.push_str(&realm.to_lowercase());
    } else {
        salt.push_str(&lowercase_username);
    }

    return salt.as_bytes().to_vec();
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_generate_aes_user_salt() {
        assert_eq!(
            "KINGDOM.HEARTSmickey".as_bytes().to_vec(),
            generate_salt("KINGdom.HEARTS", "MicKey")
        );
    }

    #[test]
    fn test_generate_aes_host_salt() {
        assert_eq!(
            "KINGDOM.HEARTShostpc.kingdom.hearts".as_bytes().to_vec(),
            generate_salt("kingdom.Hearts", "PC$")
        );
    }
}
