use smoltcp::phy;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub(crate) struct Device {
	rx_queue: Arc<Mutex<VecDeque<RxToken>>>,
	tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl Device {
	pub(crate) fn new() -> Self {		
		Device {
			rx_queue: Arc::new(Mutex::new(VecDeque::new())),
			tx_queue: Arc::new(Mutex::new(VecDeque::new())),
		}
	}

	pub(crate) fn rx_queue(&self) -> Arc<Mutex<VecDeque<RxToken>>> {
		self.rx_queue.clone()
	}

	pub(crate) fn tx_queue(&self) -> Arc<Mutex<VecDeque<Vec<u8>>>> {
		self.tx_queue.clone()
	}
}

impl<'a> phy::Device<'a> for Device {
	type RxToken = RxToken;
	type TxToken = TxToken;

	fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
		let mut rx_queue = self.rx_queue.lock().unwrap();

		let rx_token = rx_queue.pop_front()?;

		Some((rx_token, TxToken {
			tx_queue: self.tx_queue.clone(),
		}))
	}

	fn transmit(&'a mut self) -> Option<Self::TxToken> {
		Some(TxToken {
			tx_queue: self.tx_queue.clone(),
		})
	}

	fn capabilities(&self) -> phy::DeviceCapabilities {
		let mut caps = phy::DeviceCapabilities::default();

		caps.medium = phy::Medium::Ip;
		caps.max_transmission_unit = 1344;
		caps.max_burst_size = None;
		caps.checksum = phy::ChecksumCapabilities::default();
		caps.checksum.ipv4 = phy::Checksum::None;
		caps.checksum.tcp = phy::Checksum::None;

		caps
	}
}

pub(crate) struct RxToken {
	pkt: Vec<u8>,
}

impl RxToken {
	pub(crate) fn new(pkt: Vec<u8>) -> Self {
		RxToken {
			pkt,}
	}
}

impl phy::RxToken for RxToken {
	fn consume<R, F>(mut self, _timestamp: smoltcp::time::Instant, f: F) -> smoltcp::Result<R>
	where
			F: FnOnce(&mut [u8]) -> smoltcp::Result<R>
	{
		f(&mut self.pkt)
	}
}

pub(crate) struct TxToken {
	tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl phy::TxToken for TxToken {
	fn consume<R, F>(self, _timestamp: smoltcp::time::Instant, len: usize, f: F) -> smoltcp::Result<R>
	where
			F: FnOnce(&mut [u8]) -> smoltcp::Result<R>
	{
		let mut buf = vec![0;len];

		let result = f(&mut buf);

		self.tx_queue
			.lock()
			.unwrap()
			.push_back(buf);

		result
	}
}