use super::{
    credential_to_krb_cred_info_and_ticket,
    krb_cred_info_and_ticket_to_credential,
    realm_and_principal_name_to_principal,
};
use crate::{CCache, Header};
use crate::{ConvertError, ConvertResult};
use kerberos_asn1::{Asn1Object, EncKrbCredPart, EncryptedData, KrbCred};
use kerberos_constants::etypes::NO_ENCRYPTION;

pub fn ccache_to_krb_cred(ccache: CCache) -> ConvertResult<KrbCred> {
    let mut infos = Vec::new();
    let mut tickets = Vec::new();

    for credential in ccache.credentials {
        let (krb_cred_info, ticket) =
            credential_to_krb_cred_info_and_ticket(credential)?;

        infos.push(krb_cred_info);
        tickets.push(ticket);
    }

    let mut enc_krb_cred_part = EncKrbCredPart::default();
    enc_krb_cred_part.ticket_info = infos;

    let mut krb_cred = KrbCred::default();
    krb_cred.tickets = tickets;
    krb_cred.enc_part = EncryptedData {
        etype: NO_ENCRYPTION,
        kvno: None,
        cipher: enc_krb_cred_part.build(),
    };

    return Ok(krb_cred);
}

pub fn krb_cred_to_ccache(krb_cred: KrbCred) -> ConvertResult<CCache> {
    if krb_cred.enc_part.etype != NO_ENCRYPTION {
        return Err(ConvertError::KrbCredError(
            "User part is encrypted".into(),
        ));
    }

    let (_, enc_krb_cred_part) =
        EncKrbCredPart::parse(&krb_cred.enc_part.cipher)?;

    if krb_cred.tickets.len() == 0 || enc_krb_cred_part.ticket_info.len() == 0 {
        return Err(ConvertError::KrbCredError(
            "No credentials contained".into(),
        ));
    }

    let ticket_infos = enc_krb_cred_part.ticket_info;

    let realm_primary = &(&ticket_infos[0])
        .prealm
        .as_ref()
        .ok_or(ConvertError::MissingField("prealm".into()))?;

    let principal_name_primary = &(&ticket_infos[0])
        .pname
        .as_ref()
        .ok_or(ConvertError::MissingField("pname".into()))?;

    let primary_principal = realm_and_principal_name_to_principal(
        realm_primary,
        principal_name_primary,
    );

    let mut credentials = Vec::new();

    for (krb_cred_info, ticket) in
        ticket_infos.into_iter().zip(krb_cred.tickets)
    {
        let credential =
            krb_cred_info_and_ticket_to_credential(krb_cred_info, ticket)?;

        credentials.push(credential);
    }

    return Ok(CCache::new(
        Header::default(),
        primary_principal,
        credentials,
    ));
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        Address, CountedOctetString, Credential, KeyBlock, Principal, Times,
    };
    use chrono::prelude::*;
    use kerberos_asn1::*;
    use kerberos_constants::address_types::NETBIOS;
    use kerberos_constants::etypes::*;
    use kerberos_constants::principal_names::*;
    use kerberos_constants::ticket_flags;

    #[test]
    fn test_ccache_to_krb_cred() {
        let ccache = create_ccache();
        let krb_cred = create_krb_cred();

        assert_eq!(krb_cred, ccache_to_krb_cred(ccache).unwrap());
    }

    #[test]
    fn test_krb_cred_to_ccache() {
        let ccache = create_ccache();
        let krb_cred = create_krb_cred();

        assert_eq!(ccache, krb_cred_to_ccache(krb_cred).unwrap());
    }

    fn create_ccache() -> CCache {
        let realm_string =
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec());

        let client_principal = Principal::new(
            NT_PRINCIPAL as u32,
            realm_string.clone(),
            vec![CountedOctetString::new("mickey".as_bytes().to_vec())],
        );
        let server_principal = Principal::new(
            NT_SRV_INST as u32,
            realm_string.clone(),
            vec![
                CountedOctetString::new("krbtgt".as_bytes().to_vec()),
                realm_string.clone(),
            ],
        );

        let key = KeyBlock::new(AES256_CTS_HMAC_SHA1_96 as u16, vec![0x77]);

        let is_skey = 0;

        let tktflags = ticket_flags::FORWARDABLE
            | ticket_flags::RENEWABLE
            | ticket_flags::INITIAL
            | ticket_flags::PRE_AUTHENT;

        let time = Times::new(
            Utc.ymd(2019, 4, 18).and_hms(06, 00, 31).timestamp() as u32,
            Utc.ymd(2019, 4, 18).and_hms(06, 00, 31).timestamp() as u32,
            Utc.ymd(2019, 4, 18).and_hms(16, 00, 31).timestamp() as u32,
            Utc.ymd(2019, 4, 25).and_hms(06, 00, 31).timestamp() as u32,
        );

        let ticket = create_ticket(
            Realm::from("KINGDOM.HEARTS"),
            PrincipalName {
                name_type: NT_SRV_INST,
                name_string: vec![
                    KerberosString::from("krbtgt"),
                    KerberosString::from("KINGDOM.HEARTS"),
                ],
            },
        )
        .build()
        .into();

        let mut credential = Credential::new(
            client_principal.clone(),
            server_principal,
            key,
            time,
            is_skey,
            tktflags,
            ticket,
        );

        credential.addrs.push(Address::new(
            NETBIOS as u16,
            CountedOctetString::new("HOLLOWBASTION".as_bytes().to_vec()),
        ));

        let header = Header::default();

        return CCache::new(header, client_principal, vec![credential]);
    }

    fn create_krb_cred() -> KrbCred {
        let realm = Realm::from("KINGDOM.HEARTS");

        let mut sname =
            PrincipalName::new(NT_SRV_INST, KerberosString::from("krbtgt"));
        sname.push(KerberosString::from("KINGDOM.HEARTS"));

        let pname =
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from("mickey"));

        let encryption_key =
            EncryptionKey::new(AES256_CTS_HMAC_SHA1_96, vec![0x77]);

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

        return krb_cred;
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
        return KrbCredInfo {
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

    fn create_ticket(realm: Realm, pname: PrincipalName) -> Ticket {
        return Ticket::new(
            realm,
            pname,
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, None, vec![0x0]),
        );
    }

}
