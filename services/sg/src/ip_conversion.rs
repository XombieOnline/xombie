use bytes::BufMut;

use log::trace;

use nom::number::complete::{be_u16, be_u32, be_u8};

use std::mem::size_of;

use xblive::net::InAddr;
use xblive::sg;
use xblive::sg::tcp::RFC793_TCP_HEADER_LEN_IN_WORDS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4Header {
	ver_and_header_len: u8,
	dscp_and_ecn: u8,
	total_length: u16,
	id: u16,
	flags_and_header_offset: u16,
	ttl: u8,
	protocol: u8,
	header_checksum: u16,
	src_addr: [u8;4],
	dst_addr: [u8;4],
}

pub const IP_PROTOCOL_TCP: u8 = 6;

impl Ipv4Header {
	pub fn new(payload_len: u16, id: u16, protocol: u8, src_addr: [u8;4], dst_addr: [u8;4]) -> Ipv4Header {
		const IPV4_MIN_HEADER_LEN: u16 = 20;

		Ipv4Header {
			ver_and_header_len: 0x45,
			dscp_and_ecn: 0x00,
			total_length: payload_len + IPV4_MIN_HEADER_LEN,
			id,
			flags_and_header_offset: 0,
			ttl: 127,
			protocol,
			header_checksum: 0xFFFF,
			src_addr,
			dst_addr,
		}
	}

	pub fn parse<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, ver_and_header_len) = be_u8(input)?;
		let (input, dscp_and_ecn) = be_u8(input)?;
		let (input, total_length) = be_u16(input)?;
		let (input, id) = be_u16(input)?;
		let (input, flags_and_header_offset) = be_u16(input)?;
		let (input, ttl) = be_u8(input)?;
		let (input, protocol) = be_u8(input)?;
		let (input, header_checksum) = be_u16(input)?;
		let (input, src_addr) = be_u32(input)?;
		let (input, dst_addr) = be_u32(input)?;

		Ok((input, Ipv4Header {
			ver_and_header_len,
			dscp_and_ecn,
			total_length,
			id,
			flags_and_header_offset,
			ttl,
			protocol,
			header_checksum,
			src_addr: src_addr.to_be_bytes(),
			dst_addr: dst_addr.to_be_bytes(),
		}))
	}

	fn put(&self, buf: &mut Vec<u8>) {
		buf.put_u8(self.ver_and_header_len);
		buf.put_u8(self.dscp_and_ecn);
		buf.put_u16(self.total_length);
		buf.put_u16(self.id);
		buf.put_u16(self.flags_and_header_offset);
		buf.put_u8(self.ttl);
		buf.put_u8(self.protocol);
		buf.put_u16(self.header_checksum);

		buf.put(self.src_addr.as_slice());
		buf.put(self.dst_addr.as_slice());
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TcpHeader {
	src_port: u16,
	dst_port: u16,
	seq_num: u32,
	ack_num: u32,
	flags_and_data_offset: u16,
	window_size: u16,
	checksum: u16,
	urgent_pointer: u16,
}

impl TcpHeader {
	pub fn put(&self, buf: &mut Vec<u8>) {
		buf.put_u16(self.src_port);
		buf.put_u16(self.dst_port);
		buf.put_u32(self.seq_num);
		buf.put_u32(self.ack_num);
		buf.put_u16(self.flags_and_data_offset);
		buf.put_u16(self.window_size);
		buf.put_u16(self.checksum);
		buf.put_u16(self.urgent_pointer);
	}

	pub fn parse<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, src_port) = be_u16(input)?;
		let (input, dst_port) = be_u16(input)?;
		let (input, seq_num) = be_u32(input)?;
		let (input, ack_num) = be_u32(input)?;
		let (input, flags_and_data_offset) = be_u16(input)?;
		let (input, window_size) = be_u16(input)?;
		let (input, checksum) = be_u16(input)?;
		let (input, urgent_pointer) = be_u16(input)?;

		Ok((input, TcpHeader {
			src_port,
			dst_port,
			seq_num,
			ack_num,
			flags_and_data_offset,
			window_size,
			checksum,
			urgent_pointer,
		}))
	}
}

#[derive(Debug)]
pub enum ConvertTcpPacketToSgError {
	Ipv4ParseError(String),
	TcpParseError(String),
}

pub struct IpConverter {
	client_ip_id: u16,
	server_ip_id: u16,
	client_addr: InAddr,
	server_addr: InAddr,
}

impl IpConverter {
	pub fn new(client_addr: InAddr, server_addr: InAddr) -> Self {
		IpConverter {
			client_ip_id: 0xcf00,  // Chosen by fair dice roll...
			server_ip_id: 0x8600,  // .. but really just starting at set offsets so I can make sense of it in wireshark
			client_addr,
			server_addr,
		}
	}

	pub fn convert_sg_tcp_packet(
		&mut self,
		sg_tcp_header: &sg::tcp::TcpHeader,
		payload: &[u8],
		from_client: bool
	) -> Vec<u8> {
		let (ip_id, src_addr, dst_addr) = self.gen_id_src_dst(from_client);

		let payload_len = (RFC793_TCP_HEADER_LEN_IN_WORDS * size_of::<u32>()) + payload.len();	
		let payload_len = payload_len as u16;
	
		let ip_header = Ipv4Header::new(
			payload_len,
			ip_id,
			IP_PROTOCOL_TCP,
			src_addr.0,
			dst_addr.0,
		);

		let tcp_header = TcpHeader {
			src_port: sg_tcp_header.src,
			dst_port: sg_tcp_header.dst,
			seq_num: sg_tcp_header.seq_num,
			ack_num: sg_tcp_header.ack_num,
			flags_and_data_offset: sg_tcp_header.flags_and_header_size,
			window_size: sg_tcp_header.window,
			checksum: 0xFFFF,
			urgent_pointer: 0,
		};
	
		let mut buf = vec![];
	
		ip_header.put(&mut buf);
		tcp_header.put(&mut buf);
		buf.put(payload);

		buf
	}

	fn gen_id_src_dst(&mut self, from_client: bool) -> (u16, InAddr, InAddr) {
		if from_client {
			self.client_ip_id = self.client_ip_id.wrapping_add(1);

			(self.client_ip_id, self.client_addr, self.server_addr)
		} else {
			self.server_ip_id = self.server_ip_id.wrapping_add(1);

			(self.server_ip_id, self.server_addr, self.client_addr)
		}
	}
}

pub fn convert_tcp_packet<'a>(input: &'a [u8]) -> Result<(sg::tcp::TcpHeader, &'a [u8]), ConvertTcpPacketToSgError> {
	use ConvertTcpPacketToSgError::*;
	let (rem, ipv4_header) = Ipv4Header::parse(input)
		.map_err(|err| Ipv4ParseError(format!("{:x?}", err)))?;

	let (rem, tcp_header) = TcpHeader::parse(rem)
		.map_err(|err| TcpParseError(format!("{:x?}", err)))?;

	trace!("TODO: valiadate that ipv4 header is vaguely sane {:?}", ipv4_header);

	let sg_tcp_header = sg::tcp::TcpHeader {
		src: tcp_header.src_port,
		dst: tcp_header.dst_port,
		seq_num: tcp_header.seq_num,
		ack_num: tcp_header.ack_num,
		flags_and_header_size: tcp_header.flags_and_data_offset,
		window: tcp_header.window_size,
	};

	Ok((sg_tcp_header, rem))
}

#[cfg(test)]
mod tests {
	use hex_literal::hex;

	use super::*;

	#[test]
	fn parse_ipv4_header() {
		let bytes = hex!["45 00 00 28 00 00 40 00 40 06 00 00 0a 00 00 01 0a 00 00 64"];

		let (rem, parsed) = Ipv4Header::parse(&bytes).unwrap();

		assert!(rem.is_empty());

		assert_eq!(parsed, Ipv4Header {
			ver_and_header_len: 0x45,
			dscp_and_ecn: 0,
			total_length: 0x28,
			id: 0,
			flags_and_header_offset: 0x4000,
			ttl: 64,
			protocol: 6,
			header_checksum: 0,
			src_addr: [10, 0, 0, 1],
			dst_addr: [10, 0, 0, 100],
		})
	}

	#[test]
	fn parse_tcp_header() {
		let bytes = hex!["00 65 04 00 00 00 00 00 02 aa 0a b3 50 14 00 00 00 00 00 00"];

		let (rem, parsed) = TcpHeader::parse(&bytes).unwrap();

		assert!(rem.is_empty());

		assert_eq!(parsed, TcpHeader {
			src_port: 101,
			dst_port: 1024,
			seq_num: 0,
			ack_num: 0x02aa0ab3,
			flags_and_data_offset: 0x5014,
			window_size: 0,
			checksum: 0,
			urgent_pointer: 0,
		})
	}
}