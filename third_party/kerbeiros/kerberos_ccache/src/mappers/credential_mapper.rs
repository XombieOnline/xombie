use super::{
    address_vector_to_host_addresses,
    authtime_starttime_endtime_renew_till_to_times, encryption_key_to_keyblock,
    keyblock_to_encryption_key, principal_to_realm_and_principal_name,
    realm_and_principal_name_to_principal, ticket_flags_to_tktflags,
    times_to_authtime_starttime_endtime_renew_till, tktflags_to_ticket_flags,
    host_addresses_to_address_vector
};
use crate::{ConvertError, ConvertResult};
use crate::Credential;
use kerberos_asn1::{Asn1Object, KrbCredInfo, Ticket};

pub fn credential_to_krb_cred_info_and_ticket(
    credential: Credential,
) -> ConvertResult<(KrbCredInfo, Ticket)> {
    let (authtime, starttime, endtime, renew_till) =
        times_to_authtime_starttime_endtime_renew_till(&credential.time);

    let ticket_flags = tktflags_to_ticket_flags(credential.tktflags);

    let encryption_key = keyblock_to_encryption_key(credential.key);

    let (crealm, cname) =
        principal_to_realm_and_principal_name(credential.client)?;

    let (srealm, sname) =
        principal_to_realm_and_principal_name(credential.server)?;

    let caddr_result = address_vector_to_host_addresses(credential.addrs);

    let ticket_bytes = &credential.ticket.data;
    let (_, ticket) = Ticket::parse(ticket_bytes)?;

    let mut krb_cred_info = KrbCredInfo {
        key: encryption_key,
        prealm: Some(crealm),
        pname: Some(cname),
        flags: Some(ticket_flags),
        authtime: authtime,
        starttime: starttime,
        endtime: endtime,
        renew_till: renew_till,
        srealm: Some(srealm),
        sname: Some(sname),
        caddr: None,
    };

    if let Ok(caddr) = caddr_result {
        krb_cred_info.caddr = Some(caddr);
    }

    return Ok((krb_cred_info, ticket));
}

pub fn krb_cred_info_and_ticket_to_credential(
    krb_cred_info: KrbCredInfo,
    ticket: Ticket,
) -> ConvertResult<Credential> {
    let prealm = krb_cred_info
        .prealm
        .ok_or(ConvertError::MissingField("prealm".into()))?;

    let pname = krb_cred_info
        .pname
        .ok_or(ConvertError::MissingField("pname".into()))?;

    let client = realm_and_principal_name_to_principal(&prealm, &pname);

    let srealm = krb_cred_info
        .srealm
        .ok_or(ConvertError::MissingField("srealm".into()))?;

    let sname = krb_cred_info
        .sname
        .ok_or(ConvertError::MissingField("sname".into()))?;

    let server = realm_and_principal_name_to_principal(&srealm, &sname);

    let key = encryption_key_to_keyblock(krb_cred_info.key);

    let time = authtime_starttime_endtime_renew_till_to_times(
        krb_cred_info.authtime.as_ref(),
        krb_cred_info.starttime.as_ref(),
        krb_cred_info.endtime.as_ref(),
        krb_cred_info.renew_till.as_ref(),
    );

    let ticket_flags = krb_cred_info
        .flags
        .ok_or(ConvertError::MissingField("flags".into()))?;

    let tktflags = ticket_flags_to_tktflags(&ticket_flags);

    let addrs = if let Some(host_addresses) = krb_cred_info.caddr {
        host_addresses_to_address_vector(host_addresses)
    } else {
        Vec::new()
    };
     
    return Ok(Credential {
        client,
        server,
        key,
        time,
        is_skey: 0,
        tktflags,
        addrs,
        authdata: Vec::new(),
        ticket: ticket.build().into(),
        second_ticket: Vec::new().into()
    });
}
