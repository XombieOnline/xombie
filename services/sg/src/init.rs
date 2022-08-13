use kerberos_asn1::{ApReq, Authenticator, EncTicketPart, KerberosTime, Microseconds, PrincipalName};
use kerberos_constants::*;
use tokio::sync::RwLock;
use xblive::krb::service::ServiceAddress;

use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use xblive::crypto::primitives::{DiffieHellmanModulus, sha1_hmac};
use xblive::krb::gamertag_from_cname;
use xblive::sg::control::{ControlChunk, ControlPacket, DiffieHellmanControlChunk, FromRawError, KeyExXbToSgInit};

use xbox_sys::account::Xuid;
use xbox_sys::codec::Decode;
use xbox_sys::crypto::SymmetricKey;

use xombie::db;
use xombie::krb::{DecryptError, SymmetricKeyCreateError, enc_key_to_symmetric_key, krb_decrypt_and_decode, AD_TYPE_SERVICE_ADDRESSES, AT_DOMAINS};

use crate::Services;
use crate::open_clients::OpenClients;

#[derive(Debug)]
pub enum HandleControlInitError {
    CannotParsePacketHeader,
    CannotParseChunks(FromRawError),
    UnknownPacketChunkStructure(String),
    CannotDecryptTicket(DecryptError),
    UnknownTicketCName(PrincipalName),
    CannotParseSessionKey(SymmetricKeyCreateError),
    CannotDecryptAuthenticator(DecryptError),
    AuthenticationFailed(&'static str),
    DiffieHellmanGXWrongSize,
    CannotAllocateNewSpi,
    NoAdData,
    AdDataWrongType(i32),
    ServiceAddressParseError,
}

#[derive(Debug)]
pub struct ValidatedInitPacket {
    pub peer: SocketAddr,
    pub tx_socket: Arc<UdpSocket>,
    pub services: Arc<Services>,
    pub gamertag: String,
    pub xuid: Xuid,
    pub dh_g_y: DiffieHellmanModulus,
    pub spi: u32,
    pub nonce: [u8;8],
    pub ap_req_session_key: SymmetricKey,
    pub ap_req_seq_num: Option<u32>,
    pub ctime: KerberosTime,
    pub cusec: Microseconds,
    pub service_address: ServiceAddress,
}

pub async fn process_control_init_packet(buf: Vec<u8>, peer: SocketAddr, tx_socket: Arc<UdpSocket>, services: Arc<Services>, client_table: Arc<RwLock<OpenClients>>)
    -> Result<(), HandleControlInitError>
{
    use HandleControlInitError::*;

    let (_, pkt) = ControlPacket::parse(&buf[4..])
        .map_err(|_| CannotParsePacketHeader)?;

    let chunks = pkt.raw_control_chunk_iter()
        .map(|raw| ControlChunk::from_raw(raw))
        .collect::<Result<Vec<ControlChunk<'_>>, FromRawError>>()
        .map_err(|err| CannotParseChunks(err))?;

    use ControlChunk::*;
    let validated = match chunks.as_slice() {
        [KeyExXbToSgInit(init_params),
         DiffieHellman(dh),
         ApReq(ap_req),
         Padding(_)] => {
            process_control_init(init_params, dh, ap_req, peer, &buf, tx_socket, services)
                .await?
        }
        other => {
            return Err(UnknownPacketChunkStructure(
                format!("Unknown Control Packet Structure from {}: {:02x?}", peer, other)
            ))
        }
    };

    let (sg_to_client_spi, rx_queue) = client_table
        .write()
        .await
        .allocate_spi(peer)
        .ok_or(CannotAllocateNewSpi)?;

    tokio::spawn(async move {
        crate::client::start_client(validated, sg_to_client_spi, rx_queue).await
    });

    Ok(())
}

async fn process_control_init(
    init_params: &KeyExXbToSgInit,
    dh: &DiffieHellmanControlChunk<'_>,
    ap_req: &ApReq,
    peer: SocketAddr,
    buf : &[u8],
    tx_socket: Arc<UdpSocket>,
    services: Arc<Services>)
    -> Result<ValidatedInitPacket, HandleControlInitError>
{
    use HandleControlInitError::*;

    eprintln!("Recevied control init packet from {}", peer);

    const CUR_EXT_IP: [u8;4] = [192, 168, 1, 91];

    let (sg_master_key, _) = xombie::secrets::get_sg_master_key(CUR_EXT_IP)
        .await;

    let enc_ticket_part: EncTicketPart = krb_decrypt_and_decode(
        &ap_req.ticket.enc_part,
        sg_master_key,
        xombie::sg::CLIENT_TO_SG_TICKET_NONCE)
    .map_err(|err| CannotDecryptTicket(err))?;

    eprintln!("~~~TODO~~~: Validate ticket is valid");

    let ad_vec = enc_ticket_part.authorization_data
        .ok_or(NoAdData)?;

    if ad_vec.len() != 1 {
        return Err(NoAdData);
    }

    if ad_vec[0].ad_type != AD_TYPE_SERVICE_ADDRESSES {
        return Err(AdDataWrongType(ad_vec[0].ad_type))
    }

    let (_, service_address) = ServiceAddress::decode(&ad_vec[0].ad_data)
        .map_err(|_| ServiceAddressParseError)?;

    let (gamertag, _domain) = gamertag_from_cname(&enc_ticket_part.cname, AT_DOMAINS)
        .ok_or(UnknownTicketCName(enc_ticket_part.cname.clone()))?;

    let xuid = db::get_xuid_for_gamertag(&services.pg, gamertag.clone())
        .await
        .ok_or(UnknownTicketCName(enc_ticket_part.cname.clone()))?;

    eprintln!("~~~TODO~~~: Validate xuid is machine");
    eprintln!("~~~TODO~~~: Validate that machine is not banned");
    eprintln!("~~~TODO~~~: Validate that machine is not already logged in, or wait for remote connection to close");

    let session_key = enc_key_to_symmetric_key(&enc_ticket_part.key)
        .map_err(|err| CannotParseSessionKey(err))?;

    let authenticator: Authenticator = krb_decrypt_and_decode(
        &ap_req.authenticator,
        session_key,
        key_usages::KEY_USAGE_AP_REQ_AUTHEN)
    .map_err(|err| CannotDecryptAuthenticator(err))?;

    let init_params_digest = sha1_hmac(
        &session_key.0,
        &[&buf[4..128]]);

    let authenticator_cksum = authenticator.cksum.as_ref()
        .ok_or(AuthenticationFailed("No cksum field"))?;

    if authenticator_cksum.cksumtype != -131 {
        return Err(AuthenticationFailed("Wrong type for chksum"))
    }

    if !crypto::util::fixed_time_eq(&authenticator_cksum.checksum, &init_params_digest.0) {
        return Err(AuthenticationFailed("Incorrect init params checksum"));
    }

    let dh_g_y = DiffieHellmanModulus(dh.g_x.try_into()
        .map_err(|_| DiffieHellmanGXWrongSize)?);

    Ok(ValidatedInitPacket {
        peer,
        tx_socket,
        services,
        gamertag,
        xuid,
        dh_g_y,
        spi: init_params.spi,
        nonce: init_params.nonce,
        ap_req_session_key: session_key,
        ap_req_seq_num: authenticator.seq_number,
        ctime: authenticator.ctime,
        cusec: authenticator.cusec,
        service_address,
    })
}
