use hex_literal::hex;

use kerberos_asn1::{
    AsRep,
    AsReq,
    Asn1Object,
    EncAsRepPart,
    EncryptedData, 
    EncryptionKey,
    Int32,
    KerberosFlags,
    KerberosTime,
    KrbError,
    PaData,
    PrincipalName,
    Ticket};
use kerberos_constants::*;

use tokio_postgres::Client;

use xblive::crypto::derivation::generate_nonce_hmac_key;
use xblive::crypto::primitives::{rc4_md5_hmac_encrypt, verify_sha1_hmac};
use xblive::krb::*;
use xblive::user::*;

use xbox_sys::crypto::SymmetricKey;

use xombie::db;
use xombie::krb::*;

#[allow(dead_code)]
#[derive(Debug)]
struct ValidatedMacsRequestPart1 {
    stime: KerberosTime,
    rtime: Option<KerberosTime>,
    serial_number: String,
    nonce: u32,
    enc_timestamp: Vec<u8>,
    mskile_for_check_dups: Vec<u8>,
    xbox_ppa: Vec<u8>,
    xbox_client_version: Vec<u8>,
}

const EXPECTED_KDC_OPTIONS: KerberosFlags = KerberosFlags {
    flags: kdc_options::CANONICALIZE,
};

impl ValidatedMacsRequestPart1 {
    fn new(as_req: AsReq, stime: KerberosTime) -> Result<ValidatedMacsRequestPart1, KrbError> {
        let ctime = as_req.req_body.rtime.clone();
        let crealm = as_req.req_body.realm;
        let cname = as_req.req_body.cname;

        if as_req.pvno != protocol_version::PVNO {
            eprintln!("Error: Wrong pvno: {}", as_req.pvno);
            return Err(krb_error(
                error_codes::KDC_ERR_BAD_PVNO,
                ctime,
                stime,
                Some(crealm),
                cname,
                MACS_REALM.to_owned(),
                macs_sname()));
        }

        if as_req.req_body.kdc_options != EXPECTED_KDC_OPTIONS {
            eprintln!("Error: Wrong kdc_options: {:x}", as_req.req_body.kdc_options.flags);
            return Err(krb_error(
                error_codes::KDC_ERR_BADOPTION,
                ctime,
                stime,
                Some(crealm),
                cname,
                MACS_REALM.to_owned(),
                macs_sname()))
        }

        if crealm != MACS_REALM {
            eprintln!("Error: unknown realm: {}", crealm);
            return Err(krb_error(
                error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN,
                ctime,
                stime,
                Some(crealm),
                cname,
                MACS_REALM.to_owned(),
                macs_sname()))
        }

        let cname = match cname {
            Some(cname) => cname,
            None => {
                eprintln!("Error: empty cname");
                return Err(krb_error(
                    error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN,
                    ctime,
                    stime,
                    Some(crealm),
                    cname,
                    MACS_REALM.to_owned(),
                    macs_sname()))
            }
        };

        if cname.name_type != principal_names::NT_ENTERPRISE {
            eprintln!("Error: unknown cname.name_type: {}", cname.name_type);
            return Err(krb_error(
                error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN,
                ctime,
                stime,
                Some(crealm),
                Some(cname),
                MACS_REALM.to_owned(),
                macs_sname()
            ))
        }

        if cname.name_string.len() != 1 {
            return Err(krb_error(
                error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN,
                ctime,
                stime,
                Some(crealm),
                Some(cname),
                MACS_REALM.to_owned(),
                macs_sname()
            ))
        }

        let serial_number = cname.name_string[0].clone();

        if as_req.req_body.sname != Some(macs_sname()) {
            return Err(krb_error(
                error_codes::KDC_ERR_S_PRINCIPAL_UNKNOWN,
                ctime,
                stime,
                Some(crealm),
                Some(cname),
                MACS_REALM.to_owned(),
                macs_sname()
            ))
        }

        if as_req.req_body.etypes != [etypes::RC4_HMAC] {
            return Err(krb_error(
                error_codes::KDC_ERR_ETYPE_NOSUPP,
                ctime,
                stime,
                Some(crealm),
                Some(cname),
                MACS_REALM.to_owned(),
                macs_sname()
            ))
        }

        //TODO from
        //TODO till
        //TODO addresses
        //TODO enc_authorization_data
        //TODO additional_tickets

        let mut enc_timestamp: Option<Vec<u8>> = None;
        let mut mskile_for_check_dups: Option<Vec<u8>> = None;
        let mut xbox_ppa: Option<Vec<u8>> = None;
        let mut xbox_client_version: Option<Vec<u8>> = None;

        let padata = as_req.padata.as_ref().ok_or(
            krb_error(error_codes::KDC_ERR_PADATA_TYPE_NOSUPP,
                    ctime.clone(),
                    stime.clone(),
                    Some(crealm.clone()),
                    Some(cname.clone()),
                    MACS_REALM.to_owned(),
                    macs_sname()))?;

        for padata in padata {
            let which_value = match padata.padata_type {
                pa_data_types::PA_ENC_TIMESTAMP => &mut enc_timestamp,
                PA_MSKILE_FOR_CHECK_DUPS => &mut mskile_for_check_dups,
                PA_XBOX_CLIENT_VERSION => &mut xbox_client_version,
                PA_XBOX_PPA => &mut xbox_ppa,
                _ => {
                    eprintln!("Error: PA {} unknown", padata.padata_type);
                    return Err(krb_error(error_codes::KDC_ERR_PADATA_TYPE_NOSUPP,
                        ctime,
                        stime,
                        Some(crealm),
                        Some(cname),
                        MACS_REALM.to_owned(),
                        macs_sname()))
                }
            };

            if which_value.is_some() {
                eprintln!("Error: PA {} given twice", padata.padata_type);
                return Err(krb_error(error_codes::KDC_ERR_PADATA_TYPE_NOSUPP,
                    ctime,
                    stime,
                    Some(crealm),
                    Some(cname),
                    MACS_REALM.to_owned(),
                    macs_sname()))
            }

            *which_value = Some(padata.padata_value.clone());
        }

        if enc_timestamp.is_none() || mskile_for_check_dups.is_none() || xbox_ppa.is_none() || xbox_client_version.is_none() {
            eprintln!("Error: Missing required pa type: {:?} {:?} {:?} {:?}",
                enc_timestamp,
                mskile_for_check_dups,
                xbox_ppa,
                xbox_client_version);
            return Err(krb_error(error_codes::KDC_ERR_PADATA_TYPE_NOSUPP,
                ctime,
                stime,
                Some(crealm),
                Some(cname),
                MACS_REALM.to_owned(),
                macs_sname()))
        }

        Ok(ValidatedMacsRequestPart1 {
            stime,
            rtime: ctime,
            nonce: as_req.req_body.nonce,
            serial_number,
            enc_timestamp: enc_timestamp.unwrap(),
            mskile_for_check_dups: mskile_for_check_dups.unwrap(),
            xbox_ppa: xbox_ppa.unwrap(),
            xbox_client_version: xbox_client_version.unwrap(),
        })
    }

    fn create_error_from(&self, error_code: Int32) -> KrbError {
        krb_error(
            error_code,
            self.rtime.clone(),
            self.stime.clone(),
            Some(MACS_REALM.to_owned()),
            Some(self.cname()),
            MACS_REALM.to_owned(),
            macs_sname())
    }

    fn cname(&self) -> PrincipalName {
        PrincipalName {
            name_type: principal_names::NT_ENTERPRISE,
            name_string: vec![self.serial_number.clone()]
        }
    }
}

fn build_xblive_account_padata(box_info: &db::MachineInfo, session_key: SymmetricKey, nonce: u32, client_master_key: SymmetricKey) -> Result<Vec<u8>, AccountCreateError> {
    let gamertag = box_info.gamertag();
    let account = Account::new(
        box_info.xuid,
        &gamertag,
        xblive::user::DOMAIN,
        xblive::user::REALM,
        client_master_key,
    )?;

    let account_bytes: Vec<u8> = account.into();
    
    let account_encryption_key = generate_nonce_hmac_key(
        session_key,
        nonce);

    let encrypted_account = rc4_md5_hmac_encrypt(
        &account_encryption_key.0,
        ENC_NONCE_MACHINE_ACCOUNT,
        &account_bytes);

    Ok(EncryptedData {
        etype: etypes::RC4_HMAC,
        kvno: None,
        cipher: encrypted_account,
    }.build())
}

fn empty_ticket() -> Ticket {
    Ticket {
        tkt_vno: protocol_version::PVNO,
        realm: MACS_REALM.to_owned(),
        sname: macs_sname(),
        enc_part: EncryptedData {
            etype: 0,
            kvno: None,
            cipher: b"empty".to_vec(),
        }
    }
}

fn empty_enc_part(session_key: SymmetricKey, stime: KerberosTime, nonce: u32, enc_key: [u8;16]) -> EncryptedData {
    let enc_part_bytes = EncAsRepPart {
        key: EncryptionKey {
            keytype: etypes::RC4_HMAC,
            keyvalue: enc_key.to_vec(),
        },
        last_req: vec![],
        nonce,
        key_expiration: Some(unix_epoch()),
        flags: KerberosFlags {
            flags: ticket_flags::INVALID,
        },
        authtime: stime,
        starttime: None,
        endtime: unix_epoch(),
        renew_till: None,
        srealm: MACS_REALM.to_owned(),
        sname: macs_sname(),
        caddr: None,
        encrypted_pa_data: None,
    }.build();

    let encrypted = rc4_md5_hmac_encrypt(
        &session_key.0,
        8,
        &enc_part_bytes);

    EncryptedData {
        etype: etypes::RC4_HMAC,
        kvno: None,
        cipher: encrypted,
    }
}

pub async fn process_macs_request(as_req: AsReq, stime: KerberosTime, client: &Client) -> Result<AsRep, KrbError> {
    let req_part1 = ValidatedMacsRequestPart1::new(as_req, stime)?;

    let box_info = db::get_machine_info_for_serial_number(client, &req_part1.serial_number)
        .await
        .map_err(|err| {
            eprintln!("Unable to read box info {:?}", err);
            req_part1.create_error_from(error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN)
        })?;

    let (hdd_key, _) = db::get_key_for_xuid(client, box_info.xuid, db::KeyType::HddKey)
        .await
        .unwrap();

    let (online_key, _) = db::get_key_for_xuid(client, box_info.xuid, db::KeyType::OnlineKey)
        .await
        .unwrap();

    let (client_master_key, _) = db::get_key_for_xuid(client, box_info.xuid, db::KeyType::ClientMasterKey)
        .await
        .unwrap();
    
    let machine_key = xblive::crypto::derivation::generate_machine_key(
        hdd_key,
        online_key);

    let nonce_0_key = generate_nonce_hmac_key(machine_key, 0);

    if verify_sha1_hmac(&nonce_0_key.0, &req_part1.xbox_client_version).is_none() {
        return Err(req_part1.create_error_from(error_codes::KDC_ERR_PREAUTH_FAILED))
    }

    let account = build_xblive_account_padata(&box_info,
        machine_key,
        req_part1.nonce,
        client_master_key)
    .map_err(|err| {
        eprintln!("Unable to encode account: {:?}", err);
        req_part1.create_error_from(error_codes::KDC_ERR_BADOPTION)
    })?;

    Ok(AsRep {
        pvno: protocol_version::PVNO,
        msg_type: message_types::KRB_AS_REP,
        padata: Some(vec![PaData {
            padata_type: PA_XBOX_ACCOUNT_CREATION,
            padata_value: account,
        }]),
        crealm: MACS_REALM.to_owned(),
        cname: req_part1.cname(),
        ticket: empty_ticket(),
        enc_part: empty_enc_part(machine_key,
            req_part1.stime,
            req_part1.nonce,
            hex!["47 d0 5d 59 74 9a bd 27 eb 69 a2 f6 ca 81 37 c6"])
    })
}