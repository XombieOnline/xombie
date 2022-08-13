use super::super::*;
use super::*;
use kerberos_asn1::{EncKrbCredPart, EncryptedData, KrbCred, Asn1Object};
use kerberos_constants::etypes::NO_ENCRYPTION;

pub struct CredentialWarehouseKrbCredMapper {}

impl CredentialWarehouseKrbCredMapper {
    pub fn credential_warehouse_to_krb_cred(
        warehouse: &CredentialWarehouse,
    ) -> KrbCred {
        let credentials = warehouse.credentials();
        let mut seq_of_tickets = Vec::new();
        let mut seq_of_krb_cred_info = Vec::new();

        for credential in credentials.iter() {
            let (krb_cred_info, ticket) =
                CredentialKrbInfoMapper::credential_to_krb_info_and_ticket(
                    credential,
                );
            seq_of_tickets.push(ticket);
            seq_of_krb_cred_info.push(krb_cred_info);
        }

        let enc_krb_cred_part = EncKrbCredPart {
            ticket_info: seq_of_krb_cred_info,
            nonce: None,
            timestamp: None,
            usec: None,
            s_address: None,
            r_address: None,
        };

        return KrbCred::new(
            seq_of_tickets,
            EncryptedData {
                etype: NO_ENCRYPTION,
                kvno: None,
                cipher: enc_krb_cred_part.build(),
            },
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;
    use kerberos_asn1::*;
    use kerberos_constants::address_types::NETBIOS;
    use kerberos_constants::etypes::*;
    use kerberos_constants::principal_names::*;
    use kerberos_constants::ticket_flags;

    #[test]
    fn credential_warehouse_to_krb_cred() {
        let realm = Realm::from("KINGDOM.HEARTS");

        let mut sname =
            PrincipalName::new(NT_SRV_INST, KerberosString::from("krbtgt"));
        sname.push(KerberosString::from("KINGDOM.HEARTS"));

        let pname =
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from("mickey"));

        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x89, 0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 0x4e, 0x51,
                0x1e, 0xe1, 0x8f, 0xef, 0x51, 0xc4, 0xd4, 0xa5, 0xd2, 0xef,
                0x88, 0x81, 0x6d, 0xde, 0x85, 0x72, 0x5f, 0x70, 0xc2, 0x78,
                0x47, 0x86,
            ],
        );

        let auth_time =
            KerberosTime::from(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31));
        let starttime =
            KerberosTime::from(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31));
        let endtime =
            KerberosTime::from(Utc.ymd(2019, 4, 18).and_hms(16, 00, 31));
        let renew_till =
            KerberosTime::from(Utc.ymd(2019, 4, 25).and_hms(06, 00, 31));

        let caddr = vec![HostAddress::new(
            NETBIOS,
            padd_netbios_string("HOLLOWBASTION".to_string()).into_bytes(),
        )];
        let ticket_flags = TicketFlags::from(
            ticket_flags::INITIAL
                | ticket_flags::FORWARDABLE
                | ticket_flags::PRE_AUTHENT
                | ticket_flags::RENEWABLE,
        );

        let ticket_credential = create_ticket(realm.clone(), sname.clone());

        let credential = create_credential(
            encryption_key.clone(),
            realm.clone(),
            pname.clone(),
            ticket_flags.clone(),
            auth_time.clone(),
            starttime.clone(),
            endtime.clone(),
            renew_till.clone(),
            realm.clone(),
            sname.clone(),
            Some(caddr.clone()),
            ticket_credential,
        );

        let krb_cred_info = create_krb_cred_info(
            encryption_key.clone(),
            realm.clone(),
            pname.clone(),
            ticket_flags.clone(),
            auth_time.clone(),
            starttime.clone(),
            endtime.clone(),
            renew_till.clone(),
            realm.clone(),
            sname.clone(),
            caddr.clone(),
        );
        let seq_of_krb_cred_info = vec![krb_cred_info];

        let ticket = create_ticket(realm.clone(), sname.clone());
        let seq_of_tickets = vec![ticket];

        let enc_krb_cred_part = EncKrbCredPart {
            ticket_info: seq_of_krb_cred_info,
            nonce: None,
            timestamp: None,
            usec: None,
            s_address: None,
            r_address: None,
        };

        let krb_cred = KrbCred::new(
            seq_of_tickets,
            EncryptedData {
                etype: NO_ENCRYPTION,
                kvno: None,
                cipher: enc_krb_cred_part.build(),
            },
        );

        let credential_warehouse = CredentialWarehouse::from(credential);

        assert_eq!(
            krb_cred,
            CredentialWarehouseKrbCredMapper::credential_warehouse_to_krb_cred(
                &credential_warehouse
            )
        );
    }

    fn create_krb_cred_info(
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
        caddr: HostAddresses,
    ) -> KrbCredInfo {
        return  KrbCredInfo {
            key: encryption_key,
            prealm: Some(prealm),
            pname: Some(pname),
            flags: Some(ticket_flags),
            authtime: Some(authtime),
            starttime: Some(starttime),
            endtime: Some(endtime),
            renew_till: Some(renew_till),
            srealm: Some(srealm),
            sname: Some(sname),
            caddr: Some(caddr),
        };
    }

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
            caddr,
            encrypted_pa_data: None,
        };

        let credential = Credential::new(
            prealm.clone(),
            pname.clone(),
            ticket,
            enc_as_rep_part,
        );

        return credential;
    }

    fn create_ticket(realm: Realm, pname: PrincipalName) -> Ticket {
        return Ticket::new(
            realm,
            pname,
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, None, vec![0x0]),
        );
    }
}
