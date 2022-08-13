use std::convert::TryFrom;

use kerberos_asn1::PrincipalName;
use kerberos_constants::principal_names::NT_SRV_INST;

use xbox_sys::{account::*, crypto::SymmetricKey};

pub const DOMAIN: &str = "xbox.com";
pub const AT_DOMAIN: &str = "@xbox.com";
pub const REALM: &str = "passport.net";

#[derive(Debug, PartialEq)]
pub enum AccountCreateError {
    CannotEncodeGamertag,
    CannotEncodeDomain,
    CannotEncodeRealm,
}

/// User accounts kerberos server name
pub fn sname() -> PrincipalName {
    PrincipalName {
        name_type: NT_SRV_INST,
        name_string: vec![ "krbtgt".to_string(), DOMAIN.to_ascii_uppercase() ],
    }
}

/// Account struct for over wire transfer to xboxen
#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct Account {
    pub xuid: Xuid,
    pub gamertag: Gamertag,
    pub domain: Domain,
    pub realm: Realm,
    pub key: SymmetricKey,
}

impl Account {
    /// Validate and build Account
    pub fn new(xuid: Xuid, gamertag: &str, domain: &str, realm: &str, key: SymmetricKey) -> Result<Account, AccountCreateError> {
        let gamertag = Gamertag::try_from(gamertag)
            .map_err(|_| AccountCreateError::CannotEncodeGamertag)?;

        let domain = Domain::try_from(domain)
            .map_err(|_| AccountCreateError::CannotEncodeDomain)?;

        let realm = Realm::try_from(realm)
            .map_err(|_| AccountCreateError::CannotEncodeRealm)?;

        Ok(Account {
            xuid,
            gamertag,
            domain,
            realm,
            key,
        })
    }
}

impl Into<Vec<u8>> for Account {
    fn into(self) -> Vec<u8> {
        let mut ret = vec![];

        ret.append(&mut self.xuid.build());
        ret.append(&mut self.gamertag.bytes().to_vec());
        ret.append(&mut self.domain.bytes().to_vec());
        ret.append(&mut self.realm.bytes().to_vec());
        ret.append(&mut self.key.0.to_vec());

        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_account() {
        assert_eq!(Ok(Account {
            xuid: Xuid(0xFEDCBA9876543210),
            gamertag: Gamertag::try_from("tag").unwrap(),
            domain: Domain::try_from("dom").unwrap(),
            realm: Realm::try_from("rlm").unwrap(),
            key: SymmetricKey([b'B';KEY_LEN]),
        }), Account::new(
            Xuid(0xFEDCBA9876543210),
            "tag",
            "dom",
            "rlm",
            SymmetricKey([b'B';KEY_LEN])
        ))
    }
}