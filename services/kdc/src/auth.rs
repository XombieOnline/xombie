use std::convert::TryInto;

use kerberos_asn1::{Asn1Object, AsRep, AsReq, EncAsRepPart, EncTicketPart, EncryptedData, EncryptionKey, Int32, KerberosTime, KrbError, PrincipalName, Ticket, TicketFlags, TransitedEncoding, PaData};
use kerberos_constants::*;

use tokio_postgres::Client;

use xblive::crypto::derivation::generate_compound_identity_key;
use xblive::krb::{AS_TGS_REALM, PA_XBOX_CLIENT_VERSION, as_tgs_sname, PA_MSKILE_COMPOUND_IDENTITY};
use xblive::user::sname;

use xbox_sys::account::Xuid;
use xbox_sys::crypto::SymmetricKey;

use xombie::db;
use xombie::krb::*;

use crate::krb::TGS_MASTER_KEY;

const TGT_EXPIRATION_NUM_DAYS: i64 = 1;

#[allow(dead_code)]
pub struct ValidatedAsReq<'a> {
    stime: KerberosTime,
    cname: PrincipalName,
    nonce: u32,
    client_version_preauth: &'a PaData,
    timestamp_preauth: &'a PaData,
    compound_identity_preauth: Option<&'a PaData>,
}

impl<'a> ValidatedAsReq<'a> {
    fn new(as_req: &'a AsReq, stime: KerberosTime) -> Result<ValidatedAsReq<'a>, KrbError> {
        println!("as_req: {:?}", as_req);

        let cname = as_req.req_body.cname.clone().ok_or(
            krb_error(
                error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN,
                None,
                stime.clone(),
                Some(xblive::user::REALM.to_owned()),
                None,
                xblive::user::REALM.to_owned(),
                sname())
        )?;

        let client_version_preauth = find_unique_padata(PA_XBOX_CLIENT_VERSION, &as_req.padata)
            .ok_or(krb_error(
                error_codes::KDC_ERR_PREAUTH_REQUIRED,
                None,
                stime.clone(),
                Some(xblive::user::REALM.to_owned()),
                None,
                xblive::user::REALM.to_owned(),
                sname()))?;

        let timestamp_preauth = find_unique_padata(pa_data_types::PA_ENC_TIMESTAMP, &as_req.padata)
            .ok_or(krb_error(
                error_codes::KDC_ERR_PREAUTH_REQUIRED,
                None,
                stime.clone(),
                Some(xblive::user::REALM.to_owned()),
                None,
                xblive::user::REALM.to_owned(),
                sname()))?;

        let compound_identity_preauth = find_unique_padata(PA_MSKILE_COMPOUND_IDENTITY, &as_req.padata);

        Ok(ValidatedAsReq {
            stime,
            cname,
            nonce: as_req.req_body.nonce,
            client_version_preauth,
            timestamp_preauth,
            compound_identity_preauth,
        })
    }

    fn create_error_from(&self, error_code: Int32) -> KrbError {
        krb_error(
            error_code,
            None,
            self.stime.clone(),
            Some(xblive::user::REALM.to_owned()),
            Some(self.cname.clone()),
            xblive::user::REALM.to_owned(),
            sname())
    }
}

#[derive(Debug)]
pub enum CompoundIdentityExtractError {
    ParseTicketError(String),
    LeftoverBytes(usize),
    ParseEncTicketPart(String),
}

fn extract_compound_identity(compound_identity: Option<&PaData>, tgs_master_key: SymmetricKey) -> Result<Option<Vec<EncTicketPart>>, CompoundIdentityExtractError> {
    let pa_data = match compound_identity {
        None => return Ok(None),
        Some(pa_data) => pa_data
    };

    let (rem, tickets) = Vec::<Ticket>::parse(&pa_data.padata_value)
        .map_err(|err| CompoundIdentityExtractError::ParseTicketError(format!("{:?}", err)))?;

    if rem.len() != 0 {
        return Err(CompoundIdentityExtractError::LeftoverBytes(rem.len()))
    }
    
    let tickets = tickets.iter().map(|ticket| {
        krb_decrypt_and_decode::<EncTicketPart>(
            &ticket.enc_part,
            tgs_master_key,
            key_usages::KEY_USAGE_AS_REP_TICKET
        ).map_err(|err| CompoundIdentityExtractError::ParseEncTicketPart(format!("{:?}", err)))
    }).collect::<Result<Vec<EncTicketPart>, CompoundIdentityExtractError>>()?;

    Ok(Some(tickets))
}

#[derive(Debug)]
struct Keys {
    tgs_client_session_key: SymmetricKey,
    compound_key: SymmetricKey,
    tgs_master_key: SymmetricKey,
}

async fn load_and_calculate_keys(client: &Client, xuid: Xuid, compound_identity: Option<Vec<EncTicketPart>>) -> Result<Keys, ()> {
    let (tgs_client_session_key, _) = db::get_key_for_xuid(client, xuid, db::KeyType::TgsClientSessionKey)
        .await
        .unwrap();

    let (client_master_key, _) = db::get_key_for_xuid(client, xuid, db::KeyType::ClientMasterKey)
        .await
        .unwrap();

    println!("xuid: {:?}", xuid);

    let compound_key = if let Some(compound_tickets) = compound_identity {
        if compound_tickets.len() != 1 {
            panic!("too many compound tickets {:?}", compound_tickets);
        }
        generate_compound_identity_key(
            client_master_key,
            SymmetricKey(compound_tickets[0].key.keyvalue.as_slice().try_into().unwrap()))
    } else {
        client_master_key
    };

    Ok(Keys {
        tgs_client_session_key,
        compound_key,
        tgs_master_key: TGS_MASTER_KEY,
    })
}

fn validate_identity(valid_req: &ValidatedAsReq<'_>, keys: &Keys) -> Result<(), KrbError> {
    let (_, encrypted) = EncryptedData::parse(&valid_req.timestamp_preauth.padata_value)
        .unwrap();

    println!("keys: {:02x?}", keys);

    let timestamp_preauth = krb_decrypt(
        &encrypted,
        keys.compound_key,
        key_usages::KEY_USAGE_AS_REQ_TIMESTAMP
    ).unwrap();

    println!("pa_enc_timestamp: {:02x?}", timestamp_preauth);

    Ok(())
}

fn build_tgt_and_enc_part(valid_req: &ValidatedAsReq<'_>, keys: Keys) -> Result<(Ticket, EncryptedData), KrbError> {
    let endtime = KerberosTime {
        time: red_asn1::GeneralizedTime {
            time: valid_req.stime.time.checked_add_signed(chrono::Duration::days(TGT_EXPIRATION_NUM_DAYS))
                .ok_or(valid_req.create_error_from(error_codes::KDC_ERR_SVC_UNAVAILABLE))?
        }
    };

    let enc_ticket_part = EncTicketPart {
        flags: TicketFlags { flags: ticket_flags::INITIAL | ticket_flags::PRE_AUTHENT },
        key: EncryptionKey {
            keytype: etypes::RC4_HMAC,
            keyvalue: keys.tgs_client_session_key.0.to_vec(),
        },
        crealm: xblive::user::REALM.to_owned(),
        cname: valid_req.cname.clone(),
        transited: TransitedEncoding{
            tr_type: tr_types::DOMAIN_X500_COMPRESS,
            contents: format!("{}\0", xblive::user::REALM).as_bytes().to_vec(),
        },
        authtime: valid_req.stime.clone(),
        starttime: Some(valid_req.stime.clone()),
        endtime,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };

    let ticket = Ticket {
        tkt_vno: 0,
        realm: xblive::user::REALM.to_owned(),
        sname: as_tgs_sname(),
        enc_part: krb_rc4_hmac_md5(
            &enc_ticket_part.build(),
            &keys.tgs_master_key.0,
            key_usages::KEY_USAGE_AS_REP_TICKET,
            None)
    };

    let enc_as_rep_part = EncAsRepPart {
        key: EncryptionKey {
            keytype: etypes::RC4_HMAC,
            keyvalue: keys.tgs_client_session_key.0.to_vec(),
        },
        last_req: vec![],
        nonce: valid_req.nonce,
        key_expiration: None,
        flags: enc_ticket_part.flags.clone(),
        authtime: enc_ticket_part.authtime.clone(),
        starttime: enc_ticket_part.starttime.clone(),
        endtime: enc_ticket_part.endtime.clone(),
        renew_till: enc_ticket_part.renew_till.clone(),
        sname: ticket.sname.clone(),
        srealm: AS_TGS_REALM.to_owned(),
        caddr: enc_ticket_part.caddr.clone(),
        encrypted_pa_data: None,
    };

    let enc_as_rep_part = krb_rc4_hmac_md5(
        &enc_as_rep_part.build(),
        &keys.compound_key.0,
        key_usages::KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY,
        None);

    Ok((ticket, enc_as_rep_part))
}

pub async fn process_as_req(as_req: AsReq, stime: KerberosTime, client: &Client) -> Result<AsRep, KrbError> {
    let valid_req = ValidatedAsReq::new(&as_req, stime)?;

    let compound_identity_preauth = extract_compound_identity(valid_req.compound_identity_preauth, TGS_MASTER_KEY)
        .unwrap();

    let (gamertag, _domain) = xblive::krb::gamertag_from_cname(&valid_req.cname, AT_DOMAINS)
        .unwrap();

    let xuid = db::get_xuid_for_gamertag(client, gamertag)
        .await
        .unwrap();

    let keys = load_and_calculate_keys(client, xuid, compound_identity_preauth)
        .await
        .unwrap();

    validate_identity(&valid_req, &keys)?;

    let (ticket, enc_part) = build_tgt_and_enc_part(&valid_req, keys)?;

    Ok(AsRep {
        pvno: protocol_version::PVNO,
        msg_type: message_types::KRB_AS_REP,
        padata: None,
        crealm: xblive::user::REALM.to_owned(),
        cname: valid_req.cname,
        ticket,
        enc_part,
    })
}
