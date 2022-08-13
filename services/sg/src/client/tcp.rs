use async_trait::async_trait;
use tokio::sync::Mutex;

use std::collections::BTreeMap;
use std::sync::Arc;

use xblive::sg::{tcp::{TcpHeader, self, OPTION_KIND_MSS, SYN, ACK}, packet::{Opcode, PortLen}};

use crate::tracer::PcapngFile;

use super::{ClientState, PacketProcessError, send::SendCtx};

pub type ImplBuilderFn<Impl> = Box<dyn Fn() -> Result<Impl, PacketProcessError> + Send>;

#[async_trait]
pub trait ServerImpl {
    async fn on_accept(&mut self) -> Result<(), PacketProcessError>;
    async fn on_incoming_data(&mut self, data: &[u8]) -> Result<(), PacketProcessError>;
}

pub struct ServerStack<Impl: ServerImpl> {
    open_connections: BTreeMap<u16, Connection<Impl>>,
    impl_builder: ImplBuilderFn<Impl>,
}

impl<Impl: ServerImpl> ServerStack<Impl> {
    pub fn new(impl_builder: ImplBuilderFn<Impl>) -> Self {
        ServerStack {
            open_connections: BTreeMap::new(),
            impl_builder,
        }
    }

    pub async fn on_packet<'a>(&mut self, header: &TcpHeader, packet: &[u8], state: &ClientState) -> Result<(), PacketProcessError> {
        match self.open_connections.get_mut(&header.src) {
            Some(conn) => conn.on_packet(header, packet).await,
            None => {
                if header.flags() & tcp::SYN == tcp::SYN {
                    let business = (self.impl_builder)()?;

                    let conn = Connection::new(
                        header,
                        packet,
                        business,
                        state.send_ctx.clone(),
                        state.tracer.clone(),
                    ).await?;
 
                    self.open_connections.insert(header.src, conn);
                }
                Ok(())
            }
        }
    }
}

const DEFAULT_MSS: u16 = 1304;
const EMPTY_WINDOW_SIZE: u16 = 50 * DEFAULT_MSS;

#[derive(Debug)]
enum State {
    SynReceived,
    Established,
}

#[allow(dead_code)]
pub struct Connection<Impl: ServerImpl> {
    client_mss: u16,
    business: Impl,
    last_client_seq: u32,
    last_server_seq: u32,
    client_port: u16,
    server_port: u16,
    server_window: u16,
    send_ctx: Arc<SendCtx>,
    state: State,
    tracer: Option<Arc<Mutex<PcapngFile>>>,
}

impl<Impl: ServerImpl> Connection<Impl> {
    async fn new(
        header: &TcpHeader,
        packet: &[u8],
        business: Impl,
        send_ctx: Arc<SendCtx>,
        tracer: Option<Arc<Mutex<PcapngFile>>>,
    ) -> Result<Self, PacketProcessError> {
        let mut mss: Option<u16> = None;

        for option in tcp::TcpOptionsIter::new(header, packet) {
            match (option.kind, option.data.len()) {
                (OPTION_KIND_MSS, 2) => {
                    mss = Some(u16::from_be_bytes([option.data[0], option.data[1]]))
                }
                _ => {
                    println!("Unknown TCP option: {:?}", option);
                }
            }
        }

        let mut conn = Connection {
            client_mss: mss.unwrap_or(DEFAULT_MSS),
            business,
            last_client_seq: header.seq_num,
            last_server_seq: rand::random::<u32>(),
            client_port: header.src,
            server_port: header.dst,
            server_window: EMPTY_WINDOW_SIZE,
            send_ctx,
            state: State::SynReceived,
            tracer,
        };

        conn.business.on_accept()
            .await?;

        conn.send_syn_ack()
            .await?;

        Ok(conn)
    }

    async fn on_packet(&mut self, header: &TcpHeader, packet: &[u8]) -> Result<(), PacketProcessError> {
        self.state = match self.state {
            State::SynReceived => {
                if header.flags() & tcp::ACK == tcp::ACK
                    && header.ack_num == self.last_server_seq.wrapping_add(1)
                    && header.seq_num == self.last_client_seq.wrapping_add(1)
                    && header.options_length() == 0
                {
                    println!("Connection Established");
                    State::Established
                } else {
                    eprintln!("Got weird packet in syn received {:x?} {:02x?} {} {} {} {}",
                        header,
                        packet,
                        header.flags() & tcp::ACK == tcp::ACK,
                        header.ack_num == self.last_server_seq.wrapping_add(1),
                        header.seq_num == self.last_client_seq.wrapping_add(1),
                        header.options_length() == 0);
                    State::SynReceived
                }
            }
            State::Established => {
                if header.options_length() != 0 {
                    todo!()
                }

                let send_ack = self.process_incoming(header, packet)
                    .await?;

                if send_ack {
                    self.send_ack()
                        .await?;
                }

                State::Established
            }
        };

        Ok(())
    }

    async fn process_incoming(&mut self, header: &TcpHeader, packet: &[u8]) -> Result<bool, PacketProcessError> {
        if packet.len() == 0 {
            return Ok(false)
        }

        let next_seq = self.last_client_seq.wrapping_add(1);

        if header.seq_num != next_seq {
            eprintln!("dropping tcp packet {:x} {:x} {:x?} {:02x?}", next_seq, self.last_client_seq, header, packet);
            return Ok(true)
        }

        eprintln!("Received TCP data: {:x} {:x} {:x?} {:02x?}", next_seq, self.last_client_seq, header, packet);
            
        self.business.on_incoming_data(&packet)
            .await?;

        println!("{:x} {:x} {:x}", packet.len(), header.seq_num, self.last_client_seq);

        self.last_client_seq = header.seq_num.wrapping_add(packet.len() as u32).wrapping_sub(1);

        Ok(true)
    }

    async fn send_ack(&self) -> Result<(), PacketProcessError> {
        let header = self.default_tx_header(ACK);

        println!("Sending ack {:x?}", header);

        self.send_tcp_packet(header, &[])
            .await
    }

    async fn send_syn_ack(&self) -> Result<(), PacketProcessError> {
        let mss_bytes = u16::to_be_bytes(DEFAULT_MSS);

        let mss_option = &[
            OPTION_KIND_MSS,
            4,
            mss_bytes[0], mss_bytes[1],
        ];

        let mut header = self.default_tx_header(SYN | ACK);
        header.set_options_length(mss_option.len());

        self.send_tcp_packet(header, mss_option)
            .await
    }

    fn default_tx_header(&self, flags: u16) -> TcpHeader {
        let seq_num = if flags & SYN != 0 {
            self.last_server_seq
        } else {
            self.last_server_seq.wrapping_add(1)
        };

        TcpHeader {
            src: self.server_port,
            dst: self.client_port,
            seq_num,
            ack_num: self.last_client_seq.wrapping_add(1),
            flags_and_header_size: 0x5000 | flags,
            window: self.server_window,
        }
    }

    async fn send_tcp_packet(&self, header: TcpHeader, payload: &[u8]) 
        -> Result<(), PacketProcessError>
    {
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

        self.send_ctx.send_packet(opcode, payload, &protocol_footer)
            .await
    }
}
