use kerberos_asn1::{EncTgsRepPart, EncryptedData, EncryptionKey, KerberosFlags, KerberosTime, PaData, Ticket, TransitedEncoding, AuthorizationDataEntry};
use kerberos_asn1::{ApReq, Asn1Object, Authenticator, EncTicketPart, KrbError, PrincipalName, Realm, TgsRep, TgsReq};
use kerberos_constants::*;

use tokio_postgres::Client;

use xblive::crypto::derivation::generate_nonce_hmac_key;
use xblive::crypto::primitives::rc4_md5_hmac_encrypt;
use xblive::net::InAddr;
use xblive::krb::{PA_XBOX_SERVICE_ADDRESS, PA_XBOX_SERVICE_REQUEST};
use xblive::krb::gamertag_from_cname;

use xblive::krb::service::{INVALID_SERIVCE_ID, MAX_SERVICES, MAX_SERVICE_ID, ServiceAddress, ServiceRequest, ServiceResult};

use xbox_sys::account::Xuid;
use xbox_sys::crypto::SymmetricKey;
use xombie::krb::{SymmetricKeyCreateError, enc_key_to_symmetric_key};

use xombie::db;
use xombie::krb::*;
use xombie::secrets;

use crate::krb::TGS_MASTER_KEY;

#[derive(Debug)]
enum TgsProcessError {
    NoApReqPresent,
    ApReqParseError(kerberos_asn1::Error),
    UnableToValidateTicket(&'static str),
    SNameNotPresent,
    UnableToParseSessionKey(SymmetricKeyCreateError),
    UnableToDecryptServiceRequest(DecryptError),
    UnableToParseServiceRequest,
    UnableToParseServiceRequestEncData(kerberos_asn1::Error),
    InvalidServiceRequest(&'static str),
    UnableToReadListOfSecureGateways(db::ReadClusterInfoError),
    DoTheTimeWarpAgain(KerberosTime),
}

impl Into<KrbError> for TgsProcessError {
    fn into(self) -> KrbError {
        todo!("convert {:?} into a KrbError", self)
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct ValidatedRequest<'a> {
    realm: &'a str,
    crealm: Realm,
    cname: PrincipalName,
    srealm: &'a Realm,
    sname: &'a PrincipalName,
    service_request: Option<ServiceRequest>,
    service_ids: Vec<u32>,
    session_key: SymmetricKey,
    session_nonce_key: SymmetricKey,
    nonce: u32,
}

impl<'a> ValidatedRequest<'a> {
    fn new(tgs_req: &'a TgsReq) -> Result<ValidatedRequest<'a>, TgsProcessError> {
        use TgsProcessError::*;

        let ap_req_bytes = &find_unique_padata(pa_data_types::PA_TGS_REQ, &tgs_req.padata)
            .ok_or(NoApReqPresent)?
            .padata_value;

        let (_, ap_req) = ApReq::parse(ap_req_bytes.as_slice())
            .map_err(|err| ApReqParseError(err))?;

        let enc_ticket_part: EncTicketPart = krb_decrypt_and_decode(
                &ap_req.ticket.enc_part,
                TGS_MASTER_KEY,
                key_usages::KEY_USAGE_AS_REP_TICKET)
            .map_err(|_| UnableToValidateTicket("enc_ticket_part did not decode"))?;

        let authenticator_key = enc_key_to_symmetric_key(&enc_ticket_part.key)
            .map_err(|_| UnableToValidateTicket("enc_ticket key malformed"))?;

        let authenticator: Authenticator = krb_decrypt_and_decode(
                &ap_req.authenticator,
                authenticator_key,
                key_usages::KEY_USAGE_TGS_REQ_AUTHEN)
            .map_err(|_| UnableToValidateTicket("authenticator did not decrypt/decode"))?;

        let sname = tgs_req.req_body.sname.as_ref()
            .ok_or(SNameNotPresent)?;

        let session_key = enc_key_to_symmetric_key(&enc_ticket_part.key)
            .map_err(|err| UnableToParseSessionKey(err))?;

        let session_nonce_key = generate_nonce_hmac_key(
            session_key,
            tgs_req.req_body.nonce);

        println!("session_key: {:02x?}", session_key);
        println!("nonce {:08x}", tgs_req.req_body.nonce);
        println!("session_nonce_key: {:02x?}", session_nonce_key);

        let (service_request, service_ids) = if let Some(pa_data) = find_unique_padata(
            PA_XBOX_SERVICE_REQUEST,
            &tgs_req.padata)
        {
            let (_, encrypted_data) = EncryptedData::parse(&pa_data.padata_value)
                .map_err(|err| UnableToParseServiceRequestEncData(err))?;

                let service_request_plaintext = krb_decrypt(
                        &encrypted_data,
                        session_nonce_key,
                        1201)
                    .map_err(|err| UnableToDecryptServiceRequest(err))?;

                let service_request = ServiceRequest::from_raw(&&service_request_plaintext)
                    .ok_or(UnableToParseServiceRequest)?;

                if service_request.struct_version != 1 {
                    return Err(InvalidServiceRequest("unknown version"))
                }

                let num_services = service_request.num_services as usize;

                if num_services > service_request.service_id.len() {
                    return Err(InvalidServiceRequest("too many services"))
                }

                let service_ids = service_request.service_id[0..num_services].to_vec();

                (Some(service_request), service_ids)
        } else {
            (None, vec![])
        };

        Ok(ValidatedRequest {
            realm: tgs_req.req_body.realm.as_str(),
            crealm: authenticator.crealm,
            cname: authenticator.cname,
            srealm: &tgs_req.req_body.realm,
            sname,
            service_request,
            service_ids,
            session_key,
            session_nonce_key,
            nonce: tgs_req.req_body.nonce,
        })
    }
}

fn construct_pa_service_address(req: &ValidatedRequest<'_>, sg_addr: [u8;4])
    -> Result<(Option<PaData>, Option<ServiceAddress>), TgsProcessError>
{
    let service_request = match req.service_request.as_ref() {
        Some(service_request) => service_request,
        None => return Ok((None, None)),
    };

    let mut service_result = [ServiceResult {
        id: INVALID_SERIVCE_ID,
        hr: 0x8000_0000,
        port: 0,
        _rsvd_12: 0,
    }; MAX_SERVICES];

    for (i, id) in req.service_ids.iter().enumerate() {
        service_result[i].id = *id;

        match *id {
            0 => {
                service_result[i].hr = 0x8000_0001;
            }
            other if other <= MAX_SERVICE_ID => {
                service_result[i].hr = 0;
                service_result[i].port = (*id + 100) as u16;
            }
            _ => {
                eprintln!("request for unknown service id {}", *id);
                service_result[i].hr = 0x8000_0002;
            }
        } 
    }

    let mut hr_user = [0x8000_0001;4];
    for (i, id) in service_request.xuid.iter().enumerate() {
        if *id != Xuid::INVALID {
            hr_user[i] = 0;
        }
    }

    let service_address = ServiceAddress {
        hr: 0,
        hr_user,
        user_flags: [0;4],
        bw_limit: 9001,  // Do we still do 'over 9000' jokes?
        _rsvd_28: 0,
        _rsvd_2c: 0,
        _rsvd_30: 0,
        _rsvd_34: 0,
        _rsvd_38: 0,
        _rsvd_3c: 0,
        _rsvd_40: 0,
        _rsvd_44: 0,
        site_ip_address: InAddr(sg_addr),
        num_services: service_request.num_services,
        service_result,
    };

    let enc_data = EncryptedData {
        etype: etypes::RC4_HMAC,
        kvno: None,
        cipher: rc4_md5_hmac_encrypt(
            &req.session_nonce_key.0,
            1202,
            &service_address.build()),
    };

    Ok((Some(PaData {
        padata_type: PA_XBOX_SERVICE_ADDRESS,
        padata_value: enc_data.build(),
    }), Some(service_address)))
}

async fn internal_tgs_request(tgs_req: TgsReq, stime: KerberosTime, client: &Client) -> Result<TgsRep, TgsProcessError> {
    let req = ValidatedRequest::new(&tgs_req)?;
    
    let cluster_info = db::get_cluster_addrs(client)
        .await
        .map_err(|err| TgsProcessError::UnableToReadListOfSecureGateways(err))?;

    let sg_addr = cluster_info.sg_nodes[0];
    
    let (service_address_pa_data, service_address)
        = construct_pa_service_address(&req, sg_addr)?;

    let (gamertag, _domain) = gamertag_from_cname(&req.cname, AT_DOMAINS)
        .unwrap();

    let xuid = db::get_xuid_for_gamertag(client, gamertag)
        .await
        .unwrap();

    let (service_session_key, _) = db::get_key_for_xuid(client, xuid, db::KeyType::SgServiceSessionKey)
        .await
        .unwrap();

    let endtime = KerberosTime {
        time: red_asn1::GeneralizedTime{
            time: stime.time.checked_add_signed(chrono::Duration::days(1))
                .ok_or(TgsProcessError::DoTheTimeWarpAgain(stime.clone()))?,
        }
    };

    let (sg_master_key, sg_master_kvno) = secrets::get_sg_master_key(sg_addr)
        .await;

    let mut authorization_data = vec![];

    authorization_data.push(AuthorizationDataEntry {
        ad_type: AD_TYPE_USERS,
        ad_data: vec![]
    });

    if let Some(service_address) = service_address {
        authorization_data.push(AuthorizationDataEntry {
            ad_type: AD_TYPE_SERVICE_ADDRESSES,
            ad_data: service_address.build(),
        })
    }

    let enc_ticket_part = EncTicketPart {
        flags: KerberosFlags {
            flags: ticket_flags::PRE_AUTHENT,
        },
        key: EncryptionKey {
            keytype: etypes::RC4_HMAC,
            keyvalue: service_session_key.0.to_vec(),
        },
        crealm: req.crealm.clone(),
        cname: req.cname.clone(),
        transited: TransitedEncoding {
            tr_type: 0,
            contents: vec![],
        },
        authtime: stime.clone(),
        starttime: None,
        endtime: endtime.clone(),
        renew_till: None,
        caddr: None,
        authorization_data: Some(authorization_data),
    };

    let ticket = Ticket {
        tkt_vno: protocol_version::PVNO,
        realm: req.srealm.clone(),
        sname: req.sname.clone(),
        enc_part: krb_rc4_hmac_md5(
            &enc_ticket_part.build(),
            &sg_master_key.0,
            xombie::sg::CLIENT_TO_SG_TICKET_NONCE,
            sg_master_kvno)
    };

    let enc_tgs_rep_part = EncTgsRepPart {
        key: EncryptionKey {
            keytype: etypes::RC4_HMAC,
            keyvalue: service_session_key.0.to_vec(),
        },
        last_req: vec![],
        nonce: req.nonce,
        key_expiration: None,
        flags: enc_ticket_part.flags.clone(),
        authtime: enc_ticket_part.authtime.clone(),
        starttime: enc_ticket_part.starttime.clone(),
        endtime: enc_ticket_part.endtime.clone(),
        renew_till: enc_ticket_part.renew_till.clone(),
        srealm: req.srealm.clone(),
        sname: req.sname.clone(),
        caddr: None,
        encrypted_pa_data: None,
    };

    Ok(TgsRep {
        pvno: protocol_version::PVNO,
        msg_type: message_types::KRB_TGS_REP,
        padata: service_address_pa_data.map(|padata| vec![padata]),
        crealm: xblive::user::REALM.to_string(),
        cname: req.cname,
        ticket,
        enc_part: krb_rc4_hmac_md5(&enc_tgs_rep_part.build(),
            &req.session_key.0,
            key_usages::KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY,
            None)
    })
}

pub async fn process_tgs_request(tgs_req: TgsReq, stime: KerberosTime, client: &Client)
    -> Result<TgsRep, KrbError>
{
    internal_tgs_request(tgs_req, stime, client)
        .await
        .map_err(|err| err.into())
}