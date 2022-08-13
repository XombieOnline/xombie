use futures_util::stream::StreamExt;

use kerberos_asn1::{ApRep, EncApRepPart, KerberosTime, EncryptionKey};
use kerberos_constants::*;

use xblive::sg::packet::{Packet, PacketParseError, KindParseError, Kind};
use xblive::sg::seq::SeqNum;

use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::error::Error as TokioTimeError;

use tokio_util::time::delay_queue::{DelayQueue, Expired, self};

use xblive::crypto::derivation::TripleDesConnectionKeySet;
use xblive::crypto::primitives::{BlockCryptError, tdes_cbc_encrypt_in_place, DiffieHellmanModulus, DiffieHellmanResult, sha1_hmac};
use xblive::net::InAddr;
use xblive::sg::{SecurityParametersIndex, SgAddr, SgNonce};
use xblive::sg::control::{ControlChunk, KEY_EX_SG_TO_XB_RESP_FLAG_3DES, KeyExSgToXbResp, FromRawError, DiffieHellmanControlChunk};

use xbox_sys::account::Xuid;
use xbox_sys::crypto::{DesIv, SymmetricKey};

use xombie::krb::{krb_encode_and_encrypt};

use crate::init::ValidatedInitPacket;
use crate::open_clients::SpiReservation;
use crate::secrets;
use crate::tracer::PcapngFile;
use crate::Services;

use self::send::SendCtx;

mod ctrl;
mod forward;
mod local;
mod send;
mod service;
mod tcp;

#[derive(Debug)]
enum InitRespBuildError {
    CannotMarshalResponse(&'static str),
    BlockEncryptError(BlockCryptError)
}

#[derive(Debug)]
enum ClientParamsNewError {
    SocketAddrIsNotV4(SocketAddr),
}

#[derive(Clone, Debug)]
pub struct ServiceMapping {
    id: u32,
    port: u16,
}

#[derive(Debug)]
#[allow(dead_code)]
struct ClientParams {
    peer: SocketAddrV4,
    tx_socket: Arc<UdpSocket>,

    client_to_sg_spi: SecurityParametersIndex,
    sg_to_client_spi: SpiReservation,

    client_to_sg_nonce: SgNonce,
    sg_to_client_nonce: SgNonce,

    machine_user: Xuid,

    dh_x: DiffieHellmanModulus,
    dh_g_x: DiffieHellmanModulus,
    dh_g_y: DiffieHellmanModulus,
    dh_secret: DiffieHellmanModulus,

    keys: TripleDesConnectionKeySet,

    ap_req_session_key: SymmetricKey,
    ap_req_seq_num: Option<u32>,

    ctime: KerberosTime,
    cusec: i32,

    services: Vec<ServiceMapping>,
}

const FIXED_CLIENT_IN_SGADDR: InAddr = InAddr([10, 0, 0, 100]);

const FIXED_SERVER_IN_SGADDR: InAddr = InAddr([10, 0, 0, 1]);

const TIMEOUT_SECS: u16 = 60;
const PULSE_TIMEOUT_SECS: u16 = 5;

impl ClientParams {
    fn new(init_req: ValidatedInitPacket, sg_to_client_spi: SpiReservation) -> Result<Self, ClientParamsNewError> {
        let peer = match init_req.peer {
            SocketAddr::V4(v4) => v4,
            _ => return  Err(ClientParamsNewError::SocketAddrIsNotV4(init_req.peer)),
        };

        let client_to_sg_nonce = SgNonce(init_req.nonce);
        let sg_to_client_nonce = SgNonce(secrets::generate_sg_nonce());

        let dh_x = secrets::generate_dh_x();

        let dh = DiffieHellmanResult::new(dh_x, init_req.dh_g_y);

        let keys = TripleDesConnectionKeySet::generate(
            init_req.ap_req_session_key,
            dh.secret,
            client_to_sg_nonce,
            sg_to_client_nonce,
        );

        let mut services = vec![];

        for id in 0..init_req.service_address.num_services {
            let result = &init_req.service_address.service_result[id as usize];
            if result.hr == 0 {
                services.push(ServiceMapping {
                    id: result.id,
                    port: result.port,
                })
            }
        }
           
        Ok(ClientParams {
            peer,
            tx_socket: init_req.tx_socket,

            client_to_sg_spi: SecurityParametersIndex::from(init_req.spi),
            sg_to_client_spi,

            client_to_sg_nonce,
            sg_to_client_nonce,

            machine_user: init_req.xuid,

            dh_x,
            dh_g_x: dh.g_x,
            dh_g_y: init_req.dh_g_y,
            dh_secret: dh.secret,

            keys,

            ap_req_session_key: init_req.ap_req_session_key,
            ap_req_seq_num: init_req.ap_req_seq_num,

            ctime: init_req.ctime,
            cusec: init_req.cusec,

            services,
        })
    }

    fn build_init_resp(&self) -> Result<Vec<u8>, InitRespBuildError> {
        let mut buf = vec![0u8;4];
        let start_key_ex_sg_xb_chunk = buf.len();

        let key_ex_sg_to_xb_chunk = ControlChunk::KeyExSgToXbResp(KeyExSgToXbResp {
            version: 0,
            flags: KEY_EX_SG_TO_XB_RESP_FLAG_3DES,
            spi_init: self.client_to_sg_spi.into(),
            spi_resp: self.sg_to_client_spi.spi().into(),
            nonce_init: self.client_to_sg_nonce.0,
            nonce_resp: self.sg_to_client_nonce.0,
            sg_addr_init: SgAddr {
                ina_sg: FIXED_CLIENT_IN_SGADDR,
                spi_sg: self.sg_to_client_spi.spi().into(),
                xbox_id: self.machine_user,
                _rsvd_10: [0;4],
            },
            ina_init: InAddr::from(self.peer.ip()),
            port_init: self.peer.port(),
            xb_to_sg_timeout_in_secs: TIMEOUT_SECS,
            xb_to_sg_pulse_timeout_in_secs: PULSE_TIMEOUT_SECS,
            zero_pad: [0u8;2],
        });

        buf.append(&mut key_ex_sg_to_xb_chunk
            .build()
            .ok_or(InitRespBuildError::CannotMarshalResponse("KeyExSgToXbResp"))?);

        {
            let start_encrypted_range = start_key_ex_sg_xb_chunk + 0x20;
            let end_encrypted_range = start_encrypted_range + 0x20;
            let encrypted_range = &mut buf[start_encrypted_range..end_encrypted_range];

            tdes_cbc_encrypt_in_place(
                &self.keys.sg_to_client.des,
                DesIv(self.sg_to_client_nonce.0),
                encrypted_range)
                    .map_err(|err| InitRespBuildError::BlockEncryptError(err))?;
        }

        let diffie_hellman_chunk = ControlChunk::DiffieHellman(DiffieHellmanControlChunk {
            g_x: &self.dh_g_x.0
        });

        buf.append(&mut diffie_hellman_chunk
            .build()
            .ok_or(InitRespBuildError::CannotMarshalResponse("DiffieHellman"))?);

        let packet_digest = {
            let slice_to_digest = &buf[start_key_ex_sg_xb_chunk..];

            sha1_hmac(&self.ap_req_session_key.0, &[slice_to_digest])
        };

        let ap_rep_chunk = ControlChunk::ApRep(ApRep {
            pvno: protocol_version::PVNO,
            msg_type: message_types::KRB_AP_REP,
            enc_part: krb_encode_and_encrypt(EncApRepPart {
                    ctime: self.ctime.clone(),
                    cusec: self.cusec,
                    subkey: Some(EncryptionKey {
                        keytype: -131,
                        keyvalue: packet_digest.0.to_vec(),
                    }),
                    seq_number: self.ap_req_seq_num,
                },
                &self.ap_req_session_key.0,
                key_usages::KEY_USAGE_AP_REP_ENC_PART,
                None)
            }
        );

        buf.append(&mut ap_rep_chunk
            .build()
            .ok_or(InitRespBuildError::CannotMarshalResponse("ApRep"))?);

        Ok(buf)
    }

    fn net_name(&self) -> String {
        format!("[{}/{:02x?}]", self.peer, self.sg_to_client_spi.spi().0)
    }
}

#[derive(Debug)]
enum TimerExpiry {
    Overall,
}

pub struct ClientState {
    params: ClientParams,
    delay_resets: Arc<Mutex<Vec<(delay_queue::Key, Duration)>>>,
    last_seq: Arc<Mutex<SeqNum>>,
    running: AtomicBool,
    timeout_key: delay_queue::Key,

    send_ctx: Arc<SendCtx>,

    tracer: Option<Arc<Mutex<PcapngFile>>>,

    qos_state: Arc<Mutex<Option<(chrono::DateTime<chrono::Utc>, [u8;8], u16, u8)>>>,

    ext_services: Arc<Services>,
}

impl ClientState {
    fn net_name(&self) -> String {
        self.params.net_name()
    }

    async fn pump_overall_expiry(&self) {
        self.delay_resets.lock().await.push((self.timeout_key.clone(), Duration::from_secs(TIMEOUT_SECS as u64)))
    }
}

pub async fn start_client(init_req: ValidatedInitPacket, sg_to_client_spi: SpiReservation, rx_queue: UnboundedReceiver<Vec<u8>>) {
    let ext_services = init_req.services.clone();

    let params = ClientParams::new(init_req, sg_to_client_spi)
        .expect("Unable to build client params");

    let init_resp = params.build_init_resp()
        .expect("Unable to build init resp");

    let mut delay_queue = DelayQueue::new();

    let tracer = crate::tracer::PcapngFile::create_temp(
        FIXED_CLIENT_IN_SGADDR,
        FIXED_SERVER_IN_SGADDR,
    ).await.expect("Cannot create tracer");
    
    println!("{} being written to {}", params.net_name(), tracer.path());

    let tracer = Arc::new(Mutex::new(tracer));

    let timeout_key = delay_queue.insert(
        TimerExpiry::Overall,
        Duration::from_secs(TIMEOUT_SECS as u64));

    let send_peer = params.peer;
    let send_tx_socket = params.tx_socket.clone();
    let send_spi = params.client_to_sg_spi;
    let send_keys = params.keys.sg_to_client.clone();

    let state = Arc::new(ClientState {
        params: params,
        delay_resets: Arc::new(Mutex::new(vec![])),
        last_seq: Arc::new(Mutex::new(SeqNum(0))),
        running: AtomicBool::new(true),
        timeout_key,
        send_ctx: Arc::new(SendCtx::new(
            send_peer,
            send_tx_socket,
            send_spi,
            send_keys,
            Some(tracer.clone()),
        )),
        tracer: Some(tracer),
        qos_state: Arc::new(Mutex::new(None)),
        ext_services,
    });

    let mut services = service::ServiceTable::new(
        &state.params.services,
        FIXED_CLIENT_IN_SGADDR,
        FIXED_SERVER_IN_SGADDR,
        &state,
    ).expect("Unable to create serivce table");

    println!("Services {}: {:?}", state.net_name(), state.params.services);

    let _ = state.send_ctx.send_raw(&init_resp)
        .await
        .expect("Unable to send init resp");
    
    let mut rx_queue = rx_queue;

    while state.running.load(Ordering::SeqCst) {

        {
            let mut resets = state.delay_resets.lock().await;
            for (key, timeout) in resets.iter() {
                delay_queue.reset(key, *timeout)
            }

            resets.clear()
        }

        tokio::select! {
            pkt_buf = rx_queue.recv() => {
                match pkt_buf {
                    None => panic!("rx_queue for {} closed", state.net_name()),
                    Some(pkt_buf) => {
                        if let Err(err) = on_incoming_packet(pkt_buf, &state, &mut services).await {
                            eprintln!("ERROR {}: {:?}", state.net_name(), err);
                            state.running.store(false, Ordering::SeqCst);
                        }
                    }
                }
            }
            expiry = delay_queue.next() => {
                match expiry {
                    None => panic!("delay queue for {}", state.net_name()),
                    Some(expiry) => on_timer_expiry(expiry, &state).await,
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum PacketProcessError {
    ParsePacket(PacketParseError),
    ParseKind(KindParseError),
    ParseCtrl(FromRawError),
    UnknownPacketType,
    CouldNotBuild(String),
    CouldNotMarshal,
    UnauthorizedService(u16),
    Io(std::io::Error),
}

async fn on_incoming_packet<'a>(pkt_buf: Vec<u8>, state: &ClientState, services: &mut service::ServiceTable) -> Result<(), PacketProcessError> {
    use PacketProcessError::*;

    let packet = Packet::decrypt_from(
        &pkt_buf,
        state.last_seq.lock().await.clone(),
        &state.params.keys.client_to_sg)
            .map_err(|err| ParsePacket(err))?;

    let (packet, kind) = Kind::from_packet(&packet)
        .map_err(|err| ParseKind(err))?;

    println!("RX {}: {:02x?} {:02x?}",
        state.net_name(),
        kind,
        packet);

    if let Some(tracer) = &state.tracer {
        tracer.lock()
            .await
            .log(packet.payload(), &kind, true)
            .await
            .expect("Cannot trace client packet");
    }

    println!("~~~TODO~~~: Replay attack protection");

    *state.last_seq.lock().await = packet.seq_num;
    state.pump_overall_expiry().await;

    match kind {
        Kind::Control(ctrl) =>
            ctrl::on_incoming_control_packet(packet, ctrl, state)
                .await,
        Kind::Tcp(header) => {
            services.on_tcp_packet(&header, packet, state)
                .await
        }
    }
}

async fn on_timer_expiry<'a>(expiry: Result<Expired<TimerExpiry>, TokioTimeError>, state: &ClientState) {
    panic!("Expiration({}) {:?}", state.net_name(), expiry);
}
