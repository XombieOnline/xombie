use kerberos_constants::etypes::{
    RC4_HMAC, AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96
};
use kerberos_constants::kdc_options::{
  FORWARDABLE, RENEWABLE, CANONICALIZE, RENEWABLE_OK  
};
use ascii::AsciiString;
use std::collections::HashSet;
use crate::{Result};
use kerberos_crypto::is_supported_etype;

#[derive(Debug, PartialEq)]
pub(crate) struct AsReqOptions {
    realm: AsciiString,
    etypes: HashSet<i32>,
    kdc_options: u32,
    pac: bool,
}

impl AsReqOptions {
    pub fn new(realm: AsciiString) -> Self {
        return Self {
            realm,
            kdc_options: FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK,
            etypes: [AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC]
                .iter()
                .cloned()
                .collect(),
            pac: true,
        };
    }

    pub fn realm(&self) -> &AsciiString {
        return &self.realm;
    }

    pub fn etypes(&self) -> &HashSet<i32> {
        return &self.etypes;
    }

    pub fn set_etype(&mut self, etype: i32) -> Result<()> {
        return self.set_etypes([etype].iter().cloned().collect());
    }

    pub fn set_etypes(&mut self, etypes: HashSet<i32>) -> Result<()> {
        self.error_if_unsupported_etypes(&etypes)?;
        self.etypes = etypes;
        return Ok(());
    }

    fn error_if_unsupported_etypes(&self, etypes: &HashSet<i32>) -> Result<()> {
        for etype in etypes.iter() {
            self.error_if_unsupported_etype(*etype)?;
        }
        return Ok(());
    }

    fn error_if_unsupported_etype(&self, etype: i32) -> Result<()> {
        if !is_supported_etype(etype) {
            return Err(kerberos_crypto::Error::UnsupportedAlgorithm(etype))?;
        }
        return Ok(());
    }

    pub fn sorted_etypes(&self) -> Vec<i32> {
        let mut etypes_vec: Vec<i32> = Vec::new();

        if self.etypes.contains(&AES256_CTS_HMAC_SHA1_96) {
            etypes_vec.push(AES256_CTS_HMAC_SHA1_96);
        }

        if self.etypes.contains(&AES128_CTS_HMAC_SHA1_96) {
            etypes_vec.push(AES128_CTS_HMAC_SHA1_96);
        }

        if self.etypes.contains(&RC4_HMAC) {
            etypes_vec.push(RC4_HMAC);
        }

        return etypes_vec;
    }

    pub fn kdc_options(&self) -> u32 {
        return self.kdc_options;
    }

    pub fn should_be_pac_included(&self) -> bool {
        return self.pac;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::etypes::DES_CBC_MD5;

    #[test]
    fn default_etypes() {
        let options = AsReqOptions::new(AsciiString::from_ascii("").unwrap());
        let etypes: HashSet<i32> = [AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC]
            .iter()
            .cloned()
            .collect();

        assert_eq!(&etypes, options.etypes());
    }

    #[test]
    fn default_kdc_options() {
        let options = AsReqOptions::new(AsciiString::from_ascii("").unwrap());

        assert_eq!(
            FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK,
            options.kdc_options()
        );
    }

    #[test]
    fn set_etypes() {
        let mut options = AsReqOptions::new(AsciiString::from_ascii("").unwrap());

        let etypes: HashSet<i32> = [RC4_HMAC].iter().cloned().collect();

        options.set_etypes(etypes.clone()).unwrap();
        assert_eq!(&etypes, options.etypes());

        let etypes: HashSet<i32> = [AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96]
            .iter()
            .cloned()
            .collect();

        options.set_etypes(etypes.clone()).unwrap();
        assert_eq!(&etypes, options.etypes());
    }

    #[should_panic(expected = "UnsupportedAlgorithm(3)")]
    #[test]
    fn error_setting_unsupported_etypes() {
        let mut options = AsReqOptions::new(AsciiString::from_ascii("").unwrap());

        let etypes: HashSet<i32> = [RC4_HMAC, DES_CBC_MD5].iter().cloned().collect();

        options.set_etypes(etypes.clone()).unwrap();
    }

    #[test]
    fn sorted_etypes_by_strength() {
        let mut options = AsReqOptions::new(AsciiString::from_ascii("").unwrap());

        assert_eq!(
            vec![AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC],
            options.sorted_etypes()
        );

        options
            .set_etypes(
                [RC4_HMAC, AES256_CTS_HMAC_SHA1_96]
                    .iter()
                    .cloned()
                    .collect(),
            )
            .unwrap();

        assert_eq!(
            vec![AES256_CTS_HMAC_SHA1_96, RC4_HMAC],
            options.sorted_etypes()
        );
    }

    #[test]
    fn set_etype() {
        let mut options = AsReqOptions::new(AsciiString::from_ascii("").unwrap());

        let etypes: HashSet<i32> = [RC4_HMAC].iter().cloned().collect();
        options.set_etype(RC4_HMAC).unwrap();
        assert_eq!(&etypes, options.etypes());

        let etypes: HashSet<i32> = [AES128_CTS_HMAC_SHA1_96].iter().cloned().collect();
        options.set_etype(AES128_CTS_HMAC_SHA1_96).unwrap();
        assert_eq!(&etypes, options.etypes());

        let etypes: HashSet<i32> = [AES256_CTS_HMAC_SHA1_96].iter().cloned().collect();
        options.set_etype(AES256_CTS_HMAC_SHA1_96).unwrap();
        assert_eq!(&etypes, options.etypes());
    }

    #[should_panic(expected = "UnsupportedAlgorithm(3)")]
    #[test]
    fn error_setting_unsupported_etype() {
        let mut options = AsReqOptions::new(AsciiString::from_ascii("").unwrap());
        options.set_etype(DES_CBC_MD5).unwrap();
    }
}
