use super::credential_warehouse::*;
use crate::{Result, Error};
use std::fs::File;
use std::io::Write;
use kerberos_ccache::CCache;
use kerberos_asn1::Asn1Object;

pub struct CredentialFileConverter<'a> {
    credentials: &'a CredentialWarehouse,
    path: &'a str,
}

impl<'a> CredentialFileConverter<'a> {
    pub fn save_into_krb_cred_file(
        credentials: &'a CredentialWarehouse,
        path: &'a str,
    ) -> Result<()> {
        let converter = Self::new(credentials, path);
        let data = converter.build_krb_cred();
        return converter.save_data_to_file(&data);
    }

    pub fn save_into_ccache_file(
        credentials: &'a CredentialWarehouse,
        path: &'a str,
    ) -> Result<()> {
        let converter = Self::new(credentials, path);
        let data = converter.build_ccache();
        return converter.save_data_to_file(&data);
    }

    fn new(credentials: &'a CredentialWarehouse, path: &'a str) -> Self {
        return Self { credentials, path };
    }

    fn save_data_to_file(&self, data: &[u8]) -> Result<()> {
        let mut fp = File::create(self.path).map_err(|_| Error::IOError)?;

        fp.write_all(data).map_err(|_| Error::IOError)?;

        return Ok(());
    }

    fn build_krb_cred(&self) -> Vec<u8> {
        return self.credentials.into_krb_cred().build();
    }

    fn build_ccache(&self) -> Vec<u8> {
        let ccache: CCache = self.credentials.clone().into();
        return ccache.build();
    }
}
