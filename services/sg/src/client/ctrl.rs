use log::error;

use xblive::sg::control::{ControlChunk, ControlPacket, FromRawError, XbToSgPulse, SgToXbPulse, XbToSgQosInit, SgToXbQosResp};
use xblive::sg::packet::{Opcode, Packet};

use super::{ClientState, PacketProcessError};

pub async fn on_incoming_control_packet<'a>(
    _packet: &'a Packet,
    ctrl: ControlPacket<'a>,
    state: &ClientState)
-> Result<(), PacketProcessError> {
    let chunks = ctrl.raw_control_chunk_iter()
        .map(|raw| ControlChunk::from_raw(raw))
        .collect::<Result<Vec<ControlChunk<'_>>, FromRawError>>()
        .map_err(|err| PacketProcessError::ParseCtrl(err))?;

    use ControlChunk::*;
    match chunks.as_slice() {
        [Pulse] => Ok(()),
        [XbToSgPulse(pulse)] => on_incoming_xb_to_sg_pulse(pulse, state).await,
        [XbToSgQosInit(qos_init)] => on_qos_init(qos_init, state).await,
        other => {
            eprintln!("ERROR {}: Unimplemented control chunk vector: {:02x?}",
                state.net_name(),
                other);
            return Err(PacketProcessError::UnknownPacketType)
        }
    }
}

pub async fn on_incoming_xb_to_sg_pulse<'a>(pulse_in: &XbToSgPulse<'a>, state: &ClientState) -> Result<(), PacketProcessError> {
    let pulse_out = ControlChunk::SgToXbPulse(SgToXbPulse {
        seq_ack: pulse_in.seq_ack,
        events: &[],
    });

    send_single_control_chunk(pulse_out, state)
        .await
}

pub async fn on_qos_init<'a>(qos_init_pkt: &XbToSgQosInit, client_state: &ClientState) -> Result<(), PacketProcessError> {
    const SET_LOCAL_QOS_STATE: u8 = 0;
    const COMPUTE_AND_SEND_RESULTS: u8 = 1;
    const RELAY: u8 = 2;

    let mut qos_state = client_state.qos_state.lock().await;
    match qos_init_pkt.flags {
        SET_LOCAL_QOS_STATE => {
            *qos_state = Some((
                chrono::Utc::now(),
                qos_init_pkt.nonce,
                qos_init_pkt.qos_idx,
                qos_init_pkt.pkt_idx,
            ));

            Ok(())
        }

        COMPUTE_AND_SEND_RESULTS => {
            if let Some((first_time, nonce, qos_idx, pkt_idx)) = *qos_state {
                *qos_state = None;

                if nonce != qos_init_pkt.nonce || qos_idx != qos_init_pkt.qos_idx || pkt_idx != qos_init_pkt.pkt_idx {
                    error!("QOS state mismatch: {:02x?} {:02x?} {:x} {:x} {:x} {:x}",
                        nonce, qos_init_pkt.nonce,
                        qos_idx, qos_init_pkt.qos_idx,
                        pkt_idx, qos_init_pkt.pkt_idx,
                    );
                    return Ok(())
                }

                let now = chrono::Utc::now();

                let diff = now - first_time;
                let diff_us = match diff.num_microseconds() {
                    Some(us) => us as u32,
                    None => {
                        error!("QOS diff couldnt grab usecs: {}", diff);
                        return Ok(())
                    }
                };

                send_single_control_chunk(ControlChunk::SgToXbQosResp(SgToXbQosResp {
                    nonce,
                    qos_idx,
                    pkt_idx,
                    flags: 0,
                    us_rtt: diff_us,
                    us_gap: 0,
                }), client_state).await?;

                send_single_control_chunk(ControlChunk::SgToXbQosResp(SgToXbQosResp {
                    nonce,
                    qos_idx,
                    pkt_idx,
                    flags: 1,
                    us_rtt: 0,
                    us_gap: diff_us,
                }), client_state).await?;
            }

            Ok(())
        }
        RELAY => {
            send_single_control_chunk(ControlChunk::SgToXbQosResp(SgToXbQosResp {
                nonce: qos_init_pkt.nonce,
                qos_idx: qos_init_pkt.qos_idx,
                pkt_idx: qos_init_pkt.pkt_idx,
                flags: 0b_1_0000,
                us_rtt: 0,
                us_gap: 0,
            }), client_state).await?;

            Ok(())
        }
        _ => {
            error!("Unknown qos flags: {:x?}", qos_init_pkt);
            Ok(())
        }
    }
}

pub async fn send_single_control_chunk<'a>(chunk: ControlChunk<'a>, state: &ClientState) -> Result<(), PacketProcessError> {
    let payload = chunk.build()
        .ok_or(PacketProcessError::CouldNotBuild(format!("{:02x?}", chunk)))?;

    println!("TX {}: Ctrl {:02x?}", state.net_name(), payload);

    state.send_ctx.send_packet(Opcode::Control, &payload, &[]).await
}
