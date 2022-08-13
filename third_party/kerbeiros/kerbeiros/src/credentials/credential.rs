use super::credential_warehouse::CredentialWarehouse;
use crate::error;
use crate::error::Result;
use kerberos_asn1::{
    EncAsRepPart, EncryptionKey, HostAddresses,
    KerberosString, KerberosTime, LastReq, MethodData,
    PrincipalName, Realm, Ticket, TicketFlags, Asn1Object
};
use crate::mappers::{
    TimesMapper, TicketFlagsMapper, AddressMapper, AuthDataMapper, PrincipalMapper, KeyBlockMapper
};
use kerberos_ccache::{CountedOctetString, Credential as CredentialEntry};
use std::convert::TryFrom;

/// Represents a Kerberos credential, which includes one Ticket and session information.
///
/// Session information includes data such as session key, client name, realm, ticket flags and ticket expiration time.
///
/// It can be saved converted and save into Windows or Linux credential formats.
#[derive(Debug, Clone, PartialEq)]
pub struct Credential {
    crealm: Realm,
    cname: PrincipalName,
    ticket: Ticket,
    client_part: EncAsRepPart,
}

impl Credential {
    pub fn new(
        crealm: Realm,
        cname: PrincipalName,
        ticket: Ticket,
        client_part: EncAsRepPart,
    ) -> Self {
        return Self {
            crealm,
            cname,
            ticket,
            client_part,
        };
    }

    pub fn crealm(&self) -> &Realm {
        return &self.crealm;
    }

    pub fn cname(&self) -> &PrincipalName {
        return &self.cname;
    }

    pub fn ticket(&self) -> &Ticket {
        return &self.ticket;
    }

    pub fn authtime(&self) -> &KerberosTime {
        return &self.client_part.authtime;
    }

    pub fn starttime(&self) -> Option<&KerberosTime> {
        return self.client_part.starttime.as_ref();
    }

    pub fn endtime(&self) -> &KerberosTime {
        return &self.client_part.endtime;
    }

    pub fn renew_till(&self) -> Option<&KerberosTime> {
        return self.client_part.renew_till.as_ref();
    }

    pub fn flags(&self) -> &TicketFlags {
        return &self.client_part.flags;
    }

    pub fn key(&self) -> &EncryptionKey {
        return &self.client_part.key;
    }

    pub fn srealm(&self) -> &KerberosString {
        return &self.client_part.srealm;
    }

    pub fn sname(&self) -> &PrincipalName {
        return &self.client_part.sname;
    }

    pub fn caddr(&self) -> Option<&HostAddresses> {
        return self.client_part.caddr.as_ref();
    }

    pub fn encrypted_pa_data(&self) -> Option<&MethodData> {
        return self.client_part.encrypted_pa_data.as_ref();
    }

    /// Saves the credential into a file by using the ccache format, used by Linux.
    pub fn save_into_ccache_file(self, path: &str) -> Result<()> {
        return CredentialWarehouse::from(self).save_into_ccache_file(path);
    }

    /// Saves the credential into a file by using the KRB-CRED format, used by Windows.
    pub fn save_into_krb_cred_file(self, path: &str) -> Result<()> {
        return CredentialWarehouse::from(self).save_into_krb_cred_file(path);
    }
}

impl TryFrom<CredentialEntry> for Credential {
    type Error = error::Error;

    fn try_from(credential_entry: CredentialEntry) -> Result<Self> {
        let (authtime, starttime, endtime, renew_till) =
            TimesMapper::times_to_authtime_starttime_endtime_renew_till(
                &credential_entry.time,
            );

        let ticket_flags = TicketFlagsMapper::tktflags_to_ticket_flags(
            credential_entry.tktflags,
        );

        let encryption_key =
            KeyBlockMapper::keyblock_to_encryption_key(credential_entry.key);

        let (crealm, cname) =
            PrincipalMapper::principal_to_realm_and_principal_name(
                credential_entry.client,
            )?;

        let (srealm, sname) =
            PrincipalMapper::principal_to_realm_and_principal_name(
                credential_entry.server,
            )?;

        let caddr_result = AddressMapper::address_vector_to_host_addresses(
            credential_entry.addrs,
        );

        let method_data = AuthDataMapper::auth_data_vector_to_method_data(
            credential_entry.authdata,
        );

        let ticket_bytes = &credential_entry.ticket.data;
        let (_, ticket) = Ticket::parse(ticket_bytes)?;

        let mut enc_part = EncAsRepPart {
            key: encryption_key,
            last_req: LastReq::default(),
            nonce: 0,
            key_expiration: None,
            flags: ticket_flags,
            authtime,
            starttime: Some(starttime),
            endtime,
            renew_till: None,
            srealm,
            sname,
            caddr: None,
            encrypted_pa_data: None,
        };

        if let Some(time) = renew_till {
            enc_part.renew_till = Some(time);
        }

        if let Ok(caddr) = caddr_result {
            enc_part.caddr = Some(caddr);
        }

        if method_data.len() > 0 {
            enc_part.encrypted_pa_data = Some(method_data);
        }

        return Ok(Self::new(crealm, cname, ticket, enc_part));
    }
}

impl Into<CredentialEntry> for Credential {
    fn into(self) -> CredentialEntry {
        let is_skey = 0;

        let time = TimesMapper::authtime_starttime_endtime_renew_till_to_times(
            self.authtime(),
            self.starttime(),
            self.endtime(),
            self.renew_till(),
        );

        let tktflags =
            TicketFlagsMapper::ticket_flags_to_tktflags(self.flags());

        let key = KeyBlockMapper::encryption_key_to_keyblock(self.key().clone());

        let ticket = CountedOctetString::new(self.ticket().clone().build());

        let client = PrincipalMapper::realm_and_principal_name_to_principal(
            self.crealm(),
            self.cname(),
        );

        let server = PrincipalMapper::realm_and_principal_name_to_principal(
            self.srealm(),
            self.sname(),
        );

        let mut ccache_credential = CredentialEntry::new(
            client, server, key, time, is_skey, tktflags, ticket,
        );

        if let Some(caddr) = self.caddr() {
            ccache_credential.addrs =
                AddressMapper::host_addresses_to_address_vector(caddr);
        }

        if let Some(encrypted_pa_data) = self.encrypted_pa_data() {
            ccache_credential.authdata =
                AuthDataMapper::method_data_to_auth_data_vector(
                    encrypted_pa_data,
                );
        }

        return ccache_credential;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::address_types::*;
    use kerberos_constants::ticket_flags;
    use kerberos_constants::etypes::*;
    use kerberos_constants::principal_names::*;
    use kerberos_constants::pa_data_types::*;
    use kerberos_asn1::{
        EncAsRepPart, EncryptedData, EncryptionKey, HostAddress,
        HostAddresses, KerberosString, KerberosTime, LastReq, MethodData,
        PaData, KerbPaPacRequest, PrincipalName, Realm, Ticket, TicketFlags,
        padd_netbios_string
    };
    use chrono::prelude::*;
    use kerberos_ccache as ccache;
    use kerberos_ccache::{Address, AuthData};
    

    fn create_credential(
        encryption_key: EncryptionKey,
        prealm: Realm,
        pname: PrincipalName,
        ticket_flags: TicketFlags,
        authtime: KerberosTime,
        starttime: KerberosTime,
        endtime: KerberosTime,
        renew_till: KerberosTime,
        srealm: Realm,
        sname: PrincipalName,
        caddr: Option<HostAddresses>,
        method_data: MethodData,
        ticket: Ticket,
    ) -> Credential {
        let nonce = 0;
        let enc_as_rep_part = EncAsRepPart {
            key: encryption_key,
            last_req: LastReq::default(),
            nonce,
            key_expiration: None,
            flags: ticket_flags,
            authtime,
            starttime: Some(starttime),
            endtime,
            renew_till: Some(renew_till),
            srealm: srealm.clone(),
            sname: sname.clone(),
            caddr: caddr,
            encrypted_pa_data: Some(method_data),
        };

        let credential = Credential::new(
            prealm.clone(),
            pname.clone(),
            ticket,
            enc_as_rep_part,
        );

        return credential;
    }

    #[test]
    fn convert_credential_to_ccache_credential() {
        let realm = Realm::from("KINGDOM.HEARTS");

        let mut sname = PrincipalName::new(
            NT_PRINCIPAL,
            KerberosString::from("krbtgt"),
        );
        sname.push(realm.clone());

        let pname = PrincipalName::new(
            NT_PRINCIPAL,
            KerberosString::from("mickey"),
        );

        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        let key = ccache::KeyBlock::new(
            AES256_CTS_HMAC_SHA1_96 as u16,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        let authtime = Utc.ymd(2019, 7, 7).and_hms(14, 23, 33);
        let starttime = Utc.ymd(2019, 7, 7).and_hms(14, 23, 33);
        let endtime = Utc.ymd(2019, 7, 8).and_hms(0, 23, 33);
        let renew_till = Utc.ymd(2019, 7, 8).and_hms(14, 23, 30);

        let time = ccache::Times::new(
            authtime.timestamp() as u32,
            starttime.timestamp() as u32,
            endtime.timestamp() as u32,
            renew_till.timestamp() as u32,
        );

        let tktflags = ticket_flags::FORWARDABLE
            | ticket_flags::PROXIABLE
            | ticket_flags::RENEWABLE
            | ticket_flags::INITIAL
            | ticket_flags::PRE_AUTHENT;

        let ticket_flags = TicketFlags::from(tktflags);

        let mut ticket_encrypted_data =
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, None, vec![0x0a]);
        ticket_encrypted_data.kvno = Some(2);

        let ticket_credential =
            Ticket::new(realm.clone(), sname.clone(), ticket_encrypted_data);

        let host_addresses = vec![HostAddress::new(
            NETBIOS,
            padd_netbios_string("HOLLOWBASTION".to_string()).into_bytes(),
        )];
        let method_data = vec![
            PaData::new(PA_PAC_REQUEST, KerbPaPacRequest::new(true).build())
        ];

        let credential = create_credential(
            encryption_key.clone(),
            realm.clone(),
            pname.clone(),
            ticket_flags.clone(),
            authtime.into(),
            starttime.into(),
            endtime.into(),
            renew_till.into(),
            realm.clone(),
            sname.clone(),
            Some(host_addresses),
            method_data,
            ticket_credential,
        );

        let ticket = ccache::CountedOctetString::new(vec![
            0x61, 0x51, 0x30, 0x4f, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x10,
            0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48,
            0x45, 0x41, 0x52, 0x54, 0x53, 0xa2, 0x23, 0x30, 0x21, 0xa0, 0x03,
            0x02, 0x01, 0x01, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72,
            0x62, 0x74, 0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44,
            0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa3, 0x11,
            0x30, 0x0f, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x03, 0x02, 0x01,
            0x02, 0xa2, 0x03, 0x04, 0x01, 0x0a,
        ]);

        let realm_string =
            ccache::CountedOctetString::new(realm.as_bytes().to_vec());

        let client_principal = ccache::Principal::new(
            NT_PRINCIPAL as u32,
            realm_string.clone(),
            vec![ccache::CountedOctetString::new(
                "mickey".as_bytes().to_vec(),
            )],
        );
        let server_principal = ccache::Principal::new(
            NT_PRINCIPAL as u32,
            realm_string.clone(),
            vec![
                ccache::CountedOctetString::new("krbtgt".as_bytes().to_vec()),
                realm_string.clone(),
            ],
        );

        let is_skey = 0;

        let mut ccache_credential = ccache::Credential::new(
            client_principal.clone(),
            server_principal,
            key,
            time,
            is_skey,
            tktflags,
            ticket,
        );

        let mut addresses = Vec::new();
        addresses.push(Address::new(
            NETBIOS as u16,
            CountedOctetString::new("HOLLOWBASTION".as_bytes().to_vec()),
        ));
        ccache_credential.addrs = addresses;

        let mut auth_datas = Vec::new();
        auth_datas.push(AuthData::new(
            PA_PAC_REQUEST as u16,
            CountedOctetString::new(vec![
                0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff,
            ]),
        ));

        ccache_credential.authdata = auth_datas;

        assert_eq!(ccache_credential, credential.into());
    }

    #[test]
    fn test_convert_ccache_credential_to_credential() {
        let realm = Realm::from("KINGDOM.HEARTS");

        let mut sname = PrincipalName::new(
            NT_PRINCIPAL,
            KerberosString::from("krbtgt"),
        );
        sname.push(realm.clone());

        let pname = PrincipalName::new(
            NT_PRINCIPAL,
            KerberosString::from("mickey"),
        );

        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        let key = ccache::KeyBlock::new(
            AES256_CTS_HMAC_SHA1_96 as u16,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        let authtime = Utc.ymd(2019, 7, 7).and_hms(14, 23, 33);
        let starttime = Utc.ymd(2019, 7, 7).and_hms(14, 23, 33);
        let endtime = Utc.ymd(2019, 7, 8).and_hms(0, 23, 33);
        let renew_till = Utc.ymd(2019, 7, 8).and_hms(14, 23, 30);

        let time = ccache::Times::new(
            authtime.timestamp() as u32,
            starttime.timestamp() as u32,
            endtime.timestamp() as u32,
            renew_till.timestamp() as u32,
        );

        let tktflags = ticket_flags::FORWARDABLE
            | ticket_flags::PROXIABLE
            | ticket_flags::RENEWABLE
            | ticket_flags::INITIAL
            | ticket_flags::PRE_AUTHENT;

        let ticket_flags = TicketFlags::from(tktflags);

        let mut ticket_encrypted_data =
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, None, vec![0x0a]);
        ticket_encrypted_data.kvno = Some(2);

        let ticket_credential =
            Ticket::new(realm.clone(), sname.clone(), ticket_encrypted_data);

        let host_addresses = vec![HostAddress::new(
            NETBIOS,
            padd_netbios_string("HOLLOWBASTION".to_string()).into_bytes(),
        )];
        let method_data = vec![
            PaData::new(PA_PAC_REQUEST, KerbPaPacRequest::new(true).build())
        ];
        
        let credential = create_credential(
            encryption_key.clone(),
            realm.clone(),
            pname.clone(),
            ticket_flags.clone(),
            authtime.clone().into(),
            starttime.clone().into(),
            endtime.clone().into(),
            renew_till.clone().into(),
            realm.clone(),
            sname.clone(),
            Some(host_addresses),
            method_data,
            ticket_credential,
        );

        let ticket = ccache::CountedOctetString::new(vec![
            0x61, 0x51, 0x30, 0x4f, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x10,
            0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48,
            0x45, 0x41, 0x52, 0x54, 0x53, 0xa2, 0x23, 0x30, 0x21, 0xa0, 0x03,
            0x02, 0x01, 0x01, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72,
            0x62, 0x74, 0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44,
            0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa3, 0x11,
            0x30, 0x0f, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x03, 0x02, 0x01,
            0x02, 0xa2, 0x03, 0x04, 0x01, 0x0a,
        ]);

        let realm_string =
            ccache::CountedOctetString::new(realm.as_bytes().to_vec());

        let client_principal = ccache::Principal::new(
            NT_PRINCIPAL as u32,
            realm_string.clone(),
            vec![ccache::CountedOctetString::new(
                "mickey".as_bytes().to_vec(),
            )],
        );
        let server_principal = ccache::Principal::new(
            NT_PRINCIPAL as u32,
            realm_string.clone(),
            vec![
                ccache::CountedOctetString::new("krbtgt".as_bytes().to_vec()),
                realm_string.clone(),
            ],
        );

        let is_skey = 0;

        let mut ccache_credential = ccache::Credential::new(
            client_principal.clone(),
            server_principal,
            key,
            time,
            is_skey,
            tktflags,
            ticket,
        );

        let mut addresses = Vec::new();
        addresses.push(Address::new(
            NETBIOS as u16,
            CountedOctetString::new("HOLLOWBASTION".as_bytes().to_vec()),
        ));
        ccache_credential.addrs = addresses;

        let mut auth_datas = Vec::new();
        auth_datas.push(AuthData::new(
            PA_PAC_REQUEST as u16,
            CountedOctetString::new(vec![
                0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff,
            ]),
        ));

        ccache_credential.authdata = auth_datas;

        assert_eq!(
            credential,
            Credential::try_from(ccache_credential).unwrap()
        );
    }
}
