use async_trait::async_trait;

use smoltcp::wire::{IpAddress, IpCidr};

use smoltcp_user_vpn::{StackBuilder, PacketSender};
use smoltcp_user_vpn::tcp::{AcceptFn, TcpServiceConfig};

use std::sync::Arc;

use tokio::sync::mpsc;

use xblive::net::InAddr;
use xblive::sg::tcp::TcpHeader;

use crate::client::{ClientState, PacketProcessError};
use crate::client::service::Service;
use crate::ip_conversion::{IpConverter, convert_tcp_packet};

use super::send::SendCtx;

pub trait LocalTcpConnection: Send {
	fn can_recv(&mut self);

	fn can_send(&mut self);
}

pub struct LocalTcpService {
	ip_converter: IpConverter,
	rx_queue_sender: mpsc::Sender<Vec<u8>>,
}

impl LocalTcpService {
	pub fn new(client_addr: InAddr, server_addr: InAddr, port: u16, accept_fn: AcceptFn, state: &ClientState) -> Self {
		let smol_server_addr = IpAddress::v4(
			server_addr.0[0],
			server_addr.0[1],
			server_addr.0[2],
			server_addr.0[3],
		);

		let server_addrs = vec![
			IpCidr::new(smol_server_addr, 8),
		];

		let (rx_queue_sender, mut rx_queue_receiver) = mpsc::channel::<Vec<u8>>(16);

		let rx_queue = Box::pin(async_stream::stream! {
			while let Some(pkt) = rx_queue_receiver.recv().await {
				yield pkt;
			}
		});

		let tx_queue = SendCtxSender {
			send_ctx: state.send_ctx.clone(),
		};

		let mut builder = StackBuilder::new(rx_queue, tx_queue, server_addrs);
		builder.with_tcp_service(TcpServiceConfig {
			port,
			max_sockets: 16,
			accept_fn,
		});
		builder.start().unwrap();

		LocalTcpService {
			ip_converter: IpConverter::new(client_addr, server_addr),
			rx_queue_sender,
		}
	}
}

#[async_trait]
impl Service for LocalTcpService {
	async fn on_tcp_packet<'a>(&mut self, sg_tcp_header: &TcpHeader, payload: &[u8], _state: &ClientState) -> Result<(), PacketProcessError> {
		let packet = self.ip_converter.convert_sg_tcp_packet(sg_tcp_header, payload, true);
		self.rx_queue_sender
			.send(packet).await
			.map_err(|e| todo!("{:?}", e))
	}
}


struct SendCtxSender {
	send_ctx: Arc<SendCtx>,
}

fn is_tcp_ip_packet(pkt: &[u8]) -> bool {
	if pkt.len() < 20 {
		return false
	} else {
		pkt[9] == 6
	}
}

#[async_trait]
impl PacketSender for SendCtxSender {
	async fn send(&self, pkt: Vec<u8>) -> Result<(), ()> {
		if !is_tcp_ip_packet(&pkt) {
			todo!("")
		}

		let (header, payload) = convert_tcp_packet(&pkt).unwrap();
		self.send_ctx.send_tcp_packet(header, payload)
			.await.unwrap();
		
		Ok(())
	}
}