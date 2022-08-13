use log::{debug, trace};
use tokio::sync::mpsc::Receiver;

use std::collections::VecDeque;
use std::marker::Unpin;
use std::sync::{Arc, Mutex};

use smoltcp::wire::IpCidr;
use smoltcp::iface::{Interface, InterfaceBuilder, SocketHandle};

use tokio_stream::{Stream, StreamExt};

use crate::tcp::{TcpServiceConfig, TcpService};

mod device;
pub mod tcp;

#[async_trait::async_trait]
pub trait PacketSender {
	async fn send(&self, pkt: Vec<u8>) -> Result<(), ()>;
}

#[derive(Debug)]
pub(crate) enum SocketEvent {
	Buffer(Vec<u8>),
	Close,
}

struct Stack<RxQueue, TxQueue>
where
	RxQueue: Stream<Item = Vec<u8>> + Send + Unpin,
	TxQueue: PacketSender + Send + 'static,
{
	rx_queue: RxQueue,
	socket_event_receiver: Receiver<(SocketEvent, u16, SocketHandle)>,
	outgoing_tx_queue: TxQueue,
	device_rx_queue: Arc<Mutex<VecDeque<device::RxToken>>>,
	device_tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
	iface: Interface<'static, device::Device>,
	tcp_services: Vec<TcpService>,
}

impl<RxQueue, TxQueue> Stack<RxQueue, TxQueue>
where
	RxQueue: Stream<Item = Vec<u8>> + Send + Unpin,
	TxQueue: PacketSender + Send,
{
	async fn run(mut self) {
		loop {
			debug!("select loop start");
			tokio::select! {
				pkt = self.rx_queue.next() => {
					debug!("pkt");
					match pkt {
						None => {
							trace!("Closing stack for client");
							return;
						}
						Some(pkt) => {
							self.on_pkt(pkt).await
						}
					}
				}
				evt = self.socket_event_receiver.recv() => {
					debug!("tx_buf");
					match evt {
						None => {
							debug!("socket_event_receiver closed for some reason");
							return;
						}
						Some((evt, port, handle)) => {
							self.on_socket_event(evt, port, handle).await
						}
					}
				}
			}
			debug!("select loop end");
		}
	}

	async fn on_pkt(&mut self, pkt: Vec<u8>) {
		let rx_token = device::RxToken::new(pkt);

		{
			self.device_rx_queue
				.lock().unwrap()
				.push_back(rx_token);
		}

		self.pump_smol_tcp()
			.await
	}

	async fn on_socket_event(&mut self, evt: SocketEvent, port: u16, handle: SocketHandle) {
		for service in self.tcp_services.iter_mut() {
			if service.port() == port {
				service.on_socket_event(&evt, handle, &mut self.iface);
				break;
			}
		}

		self.pump_smol_tcp()
			.await
	}

	async fn pump_smol_tcp(&mut self) {
		debug!("pump smol_tcp start");
		let timestamp = smoltcp::time::Instant::now();

		let work = self.iface.poll(timestamp).unwrap();

		if work {
			for tcp_service in self.tcp_services.iter_mut() {
				tcp_service.perform_work(&mut self.iface).await
			}
		}

		self.transmit_tx_queue()
			.await;

		debug!("pump smol_tcp end");
	}

	async fn transmit_tx_queue(&mut self) {
		loop {
			let pkt = self.device_tx_queue.lock().unwrap().pop_front();

			if let Some(pkt) = pkt {
				let fut = self.outgoing_tx_queue.send(pkt);
				fut.await.unwrap();
			} else {
				return
			}
		}
	}
}

#[derive(Debug)]
pub enum StackBuildError {

}


pub struct StackBuilder<RxQueue, TxQueue>
where
	RxQueue: Stream<Item = Vec<u8>> + Send + Unpin + 'static,
	TxQueue: PacketSender + Send + 'static,
{
	rx_queue: RxQueue,
	outgoing_tx_queue: TxQueue,
	server_addrs: Vec<IpCidr>,
	tcp_services: Vec<TcpServiceConfig>,
}

impl<RxQueue, TxQueue> StackBuilder<RxQueue, TxQueue>
where
	RxQueue: Stream<Item = Vec<u8>> + Send + Unpin + 'static,
	TxQueue: PacketSender + Send + 'static,
{
	pub fn new(rx_queue: RxQueue, outgoing_tx_queue: TxQueue, server_addrs: Vec<IpCidr>) -> Self {
		StackBuilder {
			rx_queue,
			outgoing_tx_queue,
			server_addrs,
			tcp_services: vec![],
		}
	}

	pub fn with_tcp_service(&mut self, service: TcpServiceConfig) {
		self.tcp_services.push(service);
	}

	pub fn start(self) -> Result<(), ()> {
		let device = device::Device::new();
		let device_rx_queue = device.rx_queue();
		let device_tx_queue = device.tx_queue();
	
		let mut iface = InterfaceBuilder::new(device, vec![])
			.ip_addrs(self.server_addrs)
			.finalize();

		let (socket_event_sender, socket_event_receiver) = tokio::sync::mpsc::channel(16);

		let mut tcp_services = vec![];
		for config in self.tcp_services {
			tcp_services.push(TcpService::new(config, &mut iface, socket_event_sender.clone()));
		}

		let stack = Stack {
			rx_queue: self.rx_queue,
			socket_event_receiver,
			outgoing_tx_queue: self.outgoing_tx_queue,
			device_rx_queue,
			device_tx_queue,
			iface,
			tcp_services,
		};

		tokio::spawn( async move {
			stack.run().await
		});

		Ok(())
	}
}
