use std::net::SocketAddrV4;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use xblive::crypto::derivation::TripleDesOneWayKeySet;
use xblive::sg::SecurityParametersIndex;
use xblive::sg::packet::{Opcode, marshal_encrypt_and_sign_packet, PortLen};
use xblive::sg::seq::SeqNumGenerator;
use xblive::sg::tcp::TcpHeader;

use crate::tracer::PcapngFile;

use super::PacketProcessError;

pub struct SendCtx {
    peer: SocketAddrV4,
    tx_socket: Arc<UdpSocket>,
    seq_num_gen: SeqNumGenerator,
    spi: SecurityParametersIndex,
    keys: TripleDesOneWayKeySet,
    tracer: Option<Arc<Mutex<PcapngFile>>>,
}

impl SendCtx {
    pub fn new(
        peer: SocketAddrV4,
        tx_socket: Arc<UdpSocket>,
        spi: SecurityParametersIndex,
        keys: TripleDesOneWayKeySet,
        tracer: Option<Arc<Mutex<PcapngFile>>>,
    ) -> Self {
        SendCtx {
            peer,
            tx_socket,
            seq_num_gen: SeqNumGenerator::new(),
            spi,
            keys,
            tracer,
        }
    }
 
    pub async fn send_raw(&self, buf: &[u8]) -> Result<(), std::io::Error> {
        let _ = self.tx_socket.send_to(buf, self.peer)
            .await?;
        
        Ok(())
    }

    pub async fn send_packet(
        &self,
        opcode: Opcode,
        payload: &[u8],
        protocol_footer: &[u8])
    -> Result<(), PacketProcessError> {
        let seq_num = self.seq_num_gen.next();

        let pkt = marshal_encrypt_and_sign_packet(
            opcode,
            self.spi,
            payload,
            protocol_footer,
            seq_num,
            &self.keys)
                .ok_or(PacketProcessError::CouldNotMarshal)?;
        
        self.send_raw(&pkt)
            .await
            .map_err(|err| PacketProcessError::Io(err))
    }

    pub async fn send_tcp_packet(
        &self,
        header: TcpHeader,
        payload: &[u8]
    ) -> Result<(), PacketProcessError> {
        println!("send tcp packet: {:x?} {:02x?}", header, payload);

        let protocol_footer = header.build();

        let port_len = header.port_len();

        let opcode = match port_len {
            PortLen::ZeroByte => Opcode::Tcp0BytePort,
            PortLen::SingleByte => Opcode::Tcp1BytePort,
            PortLen::DoubleByte => Opcode::Tcp2BytePort,
        };

        if let Some(tracer) = &self.tracer {
            tracer.lock()
                .await
                .log(
                    payload,
                    &xblive::sg::packet::Kind::Tcp(header),
                    false
                ).await
                .expect("Could not trace sg packet");
        }

        self.send_packet(opcode, payload, &protocol_footer)
            .await
    }
}
