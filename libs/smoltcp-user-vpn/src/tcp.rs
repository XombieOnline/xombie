use log::debug;

use smoltcp::iface::{Interface, SocketHandle};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};

use tokio::sync::mpsc::{Receiver, Sender, self};

use crate::SocketEvent;
use crate::device::Device;

pub mod http;

pub type AcceptFn<E = ()> = Box<dyn FnMut(TcpStream) -> Result<(), E> + Send>;

pub struct TcpStream {
	port: u16,
	socket_handle: SocketHandle,
	rx_buf_receiver: Receiver<Vec<u8>>,
	socket_event_sender: Sender<(SocketEvent, u16, SocketHandle)>,
}

impl TcpStream {
	pub fn port(&self) -> u16 {
		self.port
	}

	pub async fn read(&mut self) -> Option<Vec<u8>> {
		self.rx_buf_receiver.recv().await
	}

	pub async fn write(&mut self, buf: Vec<u8>) {
		self.socket_event_sender.send((SocketEvent::Buffer(buf), self.port, self.socket_handle))
			.await.unwrap()
	}
}

impl Drop for TcpStream {
	fn drop(&mut self) {
		let port = self.port;
		let socket_handle = self.socket_handle.clone();
		let socket_event_sender = self.socket_event_sender.clone();
		tokio::spawn(async move {
			debug!("drop closing stream");
			socket_event_sender.send((SocketEvent::Close, port, socket_handle))
				.await.unwrap()
		});
	}
}

pub struct TcpServiceConfig {
	pub port: u16,
	pub max_sockets: usize,
	pub accept_fn: AcceptFn,
}

struct StreamInternal {
	socket_handle: SocketHandle,
	buf_sender: Option<Sender<Vec<u8>>>,
}

pub(crate) struct TcpService {
	streams: Vec<StreamInternal>,
	accept_fn: AcceptFn,
	port: u16,
	socket_event_sender: Sender<(SocketEvent, u16, SocketHandle)>,
}

impl TcpService {
	pub(crate) fn new(config: TcpServiceConfig, iface: &mut Interface<'_, Device>, socket_event_sender: Sender<(SocketEvent, u16, SocketHandle)>) -> Self {
		let mut streams = vec![];
		for _ in 0..config.max_sockets {
			let rx_buffer = TcpSocketBuffer::new(vec![0; 65536]);
			let tx_buffer = TcpSocketBuffer::new(vec![0; 65536]);
		
			let socket = TcpSocket::new(rx_buffer, tx_buffer);
	
			let socket_handle = iface.add_socket(socket);
			let socket = iface.get_socket::<TcpSocket<'_>>(socket_handle);
	
			socket.listen(config.port).unwrap();

			streams.push(StreamInternal {
				socket_handle,
				buf_sender: None,
			})
		}

		TcpService {
			streams,
			accept_fn: config.accept_fn,
			port: config.port,
			socket_event_sender,
		}
	}

	pub(crate) fn port(&self) -> u16 {
		self.port
	}

	pub(crate) async fn perform_work(&mut self, iface: &mut Interface<'_, Device>) {
		debug!("~~~~~perform work start~~~~");
		for stream in self.streams.iter_mut() {
			let socket = iface.get_socket::<TcpSocket>(stream.socket_handle);
			if socket.is_active() && stream.buf_sender.is_none() {
				let (rx_buf_sender, rx_buf_receiver) = mpsc::channel(16);
				let tcp_stream = TcpStream {
					port: self.port,
					socket_handle: stream.socket_handle,
					rx_buf_receiver,
					socket_event_sender: self.socket_event_sender.clone(),
				};
				(self.accept_fn)(tcp_stream).unwrap();
				stream.buf_sender = Some(rx_buf_sender);
				debug!("tcp:{} connected", self.port);
			} else if !socket.is_active() && stream.buf_sender.is_some() {
				stream.buf_sender = None;
				debug!("tcp:{} disconnected", self.port);
			}

			if let Some(buf_sender) = stream.buf_sender.as_ref() {
				if socket.may_recv() {
					let data = socket.recv(|buffer| {
						(buffer.len(), buffer.to_owned())
					}).unwrap();

					if data.len() > 0 {
						debug!("sending {} bytes to connection", data.len());
						buf_sender.send(data).await.unwrap()
					}
				}
			}
		}
		debug!("~~~~~perform work end~~~~");
	}

	pub(crate) fn on_socket_event(&mut self, evt: &SocketEvent, handle: SocketHandle, iface: &mut Interface<'_, Device>) {
		let socket = iface.get_socket::<TcpSocket>(handle);
		match evt {
			SocketEvent::Buffer(buf) => {
				if !socket.is_active() {
					debug!("Adding buf to inactive socket");
					return;
				}
		
				if socket.can_send() {
					let len = socket.send_slice(&buf).unwrap();
					if len != buf.len() {
						todo!("Handle overflow of tcp transmit buffer");
					}
				}		
			}
			SocketEvent::Close => {
				socket.close()
			}
		}
	}
}