use bytes::BufMut;

use nom::number::complete::{le_u16, le_u32, le_u64};

use std::mem::size_of;
use std::num::NonZeroUsize;

use xbox_sys::account::Xuid;
use xbox_sys::codec::{BufPut, Decode, parse_nul_terminated_ascii, put_nul_terminated_ascii};
use xbox_sys::crypto::SymmetricKey;
use xbox_sys::status::HResult;

use crate::addr::Addr;
use crate::crypto::primitives::KeyId;
use crate::net::InAddr;
use crate::sg::{SgAddr, SgNonce};
use crate::time::TimeStamp;
use crate::ver::LibraryVersion;

const NUL_TERMINIATOR_LEN: usize = 1;

pub const ALIVE_MSG_TYPE:       u32 = 1001;
pub const ALIVE_2_MSG_TYPE:     u32 = 1025;
pub const ALIVE_REPLY_MSG_TYPE: u32 = 1101;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
	pub header: Header,
	pub kind: MessageKind,
}

impl Message {
	pub fn reply_from_kind_and_req(kind: MessageKind, req: &Message) -> Message {
		assert!(kind.is_reply());
		assert!(req.kind.is_request());

		let len = kind.encoded_len();

		Message {
			header: Header {
				msg_type: kind.msg_type(),
				msg_len: len as u32,
				seq_num: req.header.seq_num,
				sgaddr: req.header.sgaddr,
			},
			kind,
		}
	}
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for Message {
	fn put(&self, buf: &mut AnyBufMut) {
		self.header.put(buf);
		self.kind.put(buf);
	}
}

impl Decode for Message {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, header) = Header::decode(input)?;

		let msg_len = header.msg_len as usize;

		if input.len() < msg_len {
			let needed = NonZeroUsize::new(msg_len - input.len()).unwrap();
			return Err(nom::Err::Incomplete(nom::Needed::Size(needed)))
		}

		let body = &input[..msg_len];
		let rem = &input[msg_len..];

		let kind = match header.msg_type {
			ALIVE_MSG_TYPE => {
				let (input, body) = Alive::decode(body)?;
				let (_, acct_name) = parse_nul_terminated_ascii(input)?;
				if body.nickname_len != 0 || body.title_stuff_len != 0 {
					todo!("{:?}", body);
				}
				MessageKind::Alive {
					body,
					acct_name: acct_name.to_owned(),
				}
			}
			ALIVE_2_MSG_TYPE => {
				let (input, body) = Alive2::decode(body)?;
				let (_, acct_name) = parse_nul_terminated_ascii(input)?;
				MessageKind::Alive2 {
					body,
					acct_name: acct_name.to_owned(),
				}
			}
			_ => {
				todo!("{:?} {:02x?}", header, body)
			}
		};

		Ok((rem, Message {
			header,
			kind,
		}))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageKind {
	Alive{body: Alive, acct_name: String},
	Alive2{body: Alive2, acct_name: String},
	AliveReply(AliveReply),
}

impl MessageKind {
	pub fn msg_type(&self) -> u32 {
		use MessageKind::*;
		match self {
			Alive { body: _, acct_name: _ }  => ALIVE_MSG_TYPE,
			Alive2 { body: _, acct_name: _ } => ALIVE_2_MSG_TYPE,
			AliveReply(_)                    => ALIVE_REPLY_MSG_TYPE,
		}
	}

	pub fn encoded_len(&self) -> usize {
		match self {
			MessageKind::Alive { body, acct_name } => {
				const ALIVE_HEADER_LEN: usize = 0x28;
				if body.nickname_len != 0 || body.title_stuff_len != 0 {
					todo!("{:?}", body)
				}
				ALIVE_HEADER_LEN + acct_name.as_bytes().len() + NUL_TERMINIATOR_LEN
			}
			MessageKind::Alive2 { body: _, acct_name } => {
				size_of::<Alive2>() + acct_name.as_bytes().len() + NUL_TERMINIATOR_LEN
			}
			MessageKind::AliveReply(body) => {
				const ALIVE_REPLY_HEADER_LEN: usize = 0x10;
				if body.blocks_sent != 0 || body.buddies_sent != 0 {
					todo!("{:?}", body)
				}
				ALIVE_REPLY_HEADER_LEN
			}
		}
	}

	pub fn is_request(&self) -> bool {
		use MessageKind::*;
		match self {
			Alive { body: _, acct_name: _ } => true,
			Alive2 { body: _, acct_name: _ } => true,
			AliveReply(_) => false,
		}
	}

	pub fn is_reply(&self) -> bool {
		!self.is_request()
	}
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for MessageKind {
	fn put(&self, buf: &mut AnyBufMut) {
		match self {
			Self::Alive{body, acct_name} => {
				body.put(buf);
				put_nul_terminated_ascii(acct_name, buf);
			}
			Self::Alive2{body, acct_name} => {
				body.put(buf);
				put_nul_terminated_ascii(acct_name, buf);
			}
			Self::AliveReply(body) => {
				if body.blocks_sent != 0 || body.buddies_sent != 0 {
					todo!("{:?}", body)
				}
				body.put(buf);
			}
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Header {
	pub msg_type: u32,
	pub msg_len: u32,
	pub seq_num: u32,
	pub sgaddr: SgAddr,
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for Header {
	fn put(&self, buf: &mut AnyBufMut) {
		buf.put_u32_le(self.msg_type);
		buf.put_u32_le(self.msg_len);
		buf.put_u32_le(self.seq_num);
		self.sgaddr.put(buf);
	}
}

impl Decode for Header {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, msg_type) = le_u32(input)?;
		let (input, msg_len) = le_u32(input)?;
		let (input, seq_num) = le_u32(input)?;
		let (input, sgaddr) = SgAddr::decode(input)?;

		Ok((input, Header {
			msg_type,
			msg_len,
			seq_num,
			sgaddr,
		}))
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Alive {
	pub user_id: Xuid,
	pub title_id: u32,
	pub acct_name_len: u16,
	pub buddy_list_version: u32,
	pub block_list_version: u32,
	pub state: u32,
	pub match_session_id: u64,
	pub nickname_len: u16,
	pub title_stuff_len: u16,
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for Alive {
	fn put(&self, buf: &mut AnyBufMut) {
		self.user_id.put(buf);
		buf.put_u32_le(self.title_id);
		buf.put_u16_le(self.acct_name_len);
		buf.put_u32_le(self.buddy_list_version);
		buf.put_u32_le(self.block_list_version);
		buf.put_u32_le(self.state);
		buf.put_u64_le(self.match_session_id);
		buf.put_u16_le(self.nickname_len);
		buf.put_u16_le(self.title_stuff_len);
	}
}

impl Decode for Alive {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, user_id) = Xuid::decode(input)?;
		let (input, title_id) = le_u32(input)?;
		let (input, acct_name_len) = le_u16(input)?;
		let (input, buddy_list_version) = le_u32(input)?;
		let (input, block_list_version) = le_u32(input)?;
		let (input, state) = le_u32(input)?;
		let (input, match_session_id) = le_u64(input)?;
		let (input, nickname_len) = le_u16(input)?;
		let (input, title_stuff_len) = le_u16(input)?;

		Ok((input, Alive {
			user_id,
			title_id,
			acct_name_len,
			buddy_list_version,
			block_list_version,
			state,
			match_session_id,
			nickname_len,
			title_stuff_len,
		}))
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Alive2 {
	pub user_id: Xuid,
	pub acct_name_len: u16,
	pub xnaddr: Addr,
	pub xnkid: KeyId,
	pub xnkey: SymmetricKey,
	pub buddy_list_version: u32,
	pub block_list_version: u32,
	pub client_version: LibraryVersion,
	pub title_id: u32,
	pub title_version: u32,
	pub title_region: u32,
	pub port: u16,
	pub ip_al: InAddr,
	pub nonce: SgNonce,
	pub time_init: TimeStamp,
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for Alive2 {
	fn put(&self, buf: &mut AnyBufMut) {
		self.user_id.put(buf);
		buf.put_u16_le(self.acct_name_len);
		self.xnaddr.put(buf);
		self.xnkid.put(buf);
		self.xnkey.put(buf);
		buf.put_u32_le(self.buddy_list_version);
		buf.put_u32_le(self.block_list_version);
		self.client_version.put(buf);
		buf.put_u32_le(self.title_id);
		buf.put_u32_le(self.title_version);
		buf.put_u32_le(self.title_region);
		buf.put_u16_le(self.port);
		self.ip_al.put(buf);
		self.nonce.put(buf);
		self.time_init.put(buf);
	}
}

impl Decode for Alive2 {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, user_id) = Xuid::decode(input)?;
		let (input, acct_name_len) = le_u16(input)?;
		let (input, xnaddr) = Addr::decode(input)?;
		let (input, xnkid) = KeyId::decode(input)?;
		let (input, xnkey) = SymmetricKey::decode(input)?;
		let (input, buddy_list_version) = le_u32(input)?;
		let (input, block_list_version) = le_u32(input)?;
		let (input, client_version) = LibraryVersion::decode(input)?;
		let (input, title_id) = le_u32(input)?;
		let (input, title_version) = le_u32(input)?;
		let (input, title_region) = le_u32(input)?;
		let (input, port) = le_u16(input)?;
		let (input, ip_al) = InAddr::decode(input)?;
		let (input, nonce) = SgNonce::decode(input)?;
		let (input, time_init) = TimeStamp::decode(input)?;

		Ok((input, Alive2 {
			user_id,
			acct_name_len,
			xnaddr,
			xnkid,
			xnkey,
			buddy_list_version,
			block_list_version,
			client_version,
			title_id,
			title_version,
			title_region,
			port,
			ip_al,
			nonce,
			time_init,
		}))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct AliveReply {
	pub hr: HResult,
	pub buddy_list_version: u32,
	pub buddies_sent: u16,
	pub block_list_version: u32,
	pub blocks_sent: u16,
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for AliveReply {
	fn put(&self, buf: &mut AnyBufMut) {
		self.hr.put(buf);
		buf.put_u32_le(self.buddy_list_version);
		buf.put_u16_le(self.buddies_sent);
		buf.put_u32_le(self.block_list_version);
		buf.put_u16_le(self.blocks_sent);
	}
}

impl Decode for AliveReply {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, hr) = HResult::decode(input)?;
		let (input, buddy_list_version) = le_u32(input)?;
		let (input, buddies_sent) = le_u16(input)?;
		let (input, block_list_version) = le_u32(input)?;
		let (input, blocks_sent) = le_u16(input)?;

		Ok((input, AliveReply {
			hr,
			buddy_list_version,
			buddies_sent,
			block_list_version,
			blocks_sent,
		}))
	}
}

#[cfg(test)]
mod tests {
	use hex_literal::hex;

	use xbox_sys::codec::test_codec;
	use xbox_sys::crypto::SYMMETRIC_KEY_LEN;

	use crate::crypto::primitives::KEY_ID_LENGTH;
	use crate::net::Eui48;
	use crate::sg::SG_NONCE_LEN;

	use super::*;

	#[test]
	fn alive2_message_codec() {
		test_codec(
			&hex!["
				0104000081000000010000000a000064
				00010000010000000000000000000000

				3292446c9074090009000a00020fc0a8
				015bbbbe0050f21f64530a0000640001
				000001000000000000000000000082bb
				78b11ec1da0539376321974612e22d12
				25f8c6f9c6cc00000000000000000000
				0000000000000000feff000000000000
				00000000000000000000000000000000
				0000000000000000

				6d6f6e6f6361736100
			"], Message {
				header: Header {
					msg_type: 0x401,
					msg_len: 0x81,
					seq_num: 1,
					sgaddr: SgAddr {
						ina_sg: InAddr([10, 0, 0, 100]),
						spi_sg: 0x00000100,
						xbox_id: Xuid(1),
						_rsvd_10: [0;4],
					},
				},
				kind: MessageKind::Alive2 {
					body: Alive2 {
						user_id: Xuid(0x000974906c449232),
						acct_name_len: 9,
						xnaddr: Addr {
							addr: InAddr([10, 0, 2, 15]),
							addr_online: InAddr([192, 168, 1, 91]),
							port_online: 0xbebb,
							enet: Eui48(hex!["00 50 f2 1f 64 53"]),
							online: hex!["0a000064 00010000 01000000 00000000 00000000"],
						},
						xnkid: KeyId(hex!["82bb78b11ec1da05"]),
						xnkey: SymmetricKey(hex!["39376321974612e22d1225f8c6f9c6cc"]),
						buddy_list_version: 0,
						block_list_version: 0,
						client_version: LibraryVersion {
							major: 0,
							minor: 0,
							build: 0,
							qfe: 0,
						},
						title_id: 0xfffe0000,
						title_version: 0,
						title_region: 0,
						ip_al: InAddr([0, 0, 0, 0]),
						port: 0,
						nonce: SgNonce(hex!["0000000000000000"]),
						time_init: TimeStamp(0),
					},
					acct_name: "monocasa".to_owned(),
				}
			}
		);
	}

	#[test]
	fn header_codec() {
		test_codec(
			&hex!["
				01040000
				81000000
				01000000
				0a000064
				00010000
				0100000000000000
				00000000
			"], Header {
				msg_type: 0x401,
				msg_len: 0x81,
				seq_num: 1,
				sgaddr: SgAddr {
					ina_sg: InAddr([10, 0, 0, 100]),
					spi_sg: 0x00000100,
					xbox_id: Xuid(1),
					_rsvd_10: [0;4],
				}
			}
		);
	}

	#[test]
	fn alive_codec() {
		test_codec(
			&hex!["
				32 92 44 6c 90 74 09 00
				0b 00 41 4c
				09 00
				00 00 00 00
				00 00 00 00
				05 00 00 00
				00 00 00 00 00 00 00 00
				00 00
				00 00
			"], Alive {
				user_id: Xuid(0x000974906c449232),
				title_id: 0x4c41000b,
				acct_name_len: 9,
				buddy_list_version: 0,
				block_list_version: 0,
				state: 5,
				match_session_id: 0,
				nickname_len: 0,
				title_stuff_len: 0,
			}
		)
	}

	#[test]
	fn alive_message_codec() {
		test_codec(
			&hex!["
				e90300002f000000010000000a000064
				00010000010000000000000000000000
				
				3292446c907409000b00414c09000000
				00000000000005000000000000000000
				0000000000006d6f6e6f6361736100
			"], Message {
				header: Header {
					msg_type: ALIVE_MSG_TYPE,
					msg_len: 0x2f,
					seq_num: 1,
					sgaddr: SgAddr {
						ina_sg: InAddr([10, 0, 0, 100]),
						spi_sg: 256,
						xbox_id: Xuid(1),
						_rsvd_10: [0;4]
					}
				},
				kind: MessageKind::Alive {
					body: Alive {
						user_id: Xuid(0x000974906c449232),
						title_id: 0x4c41000b,
						acct_name_len: 9,
						buddy_list_version: 0,
						block_list_version: 0,
						state: 5,
						match_session_id: 0,
						nickname_len: 0,
						title_stuff_len: 0,
					},
					acct_name: "monocasa".to_owned(),
				}
			}
		)
	}

	#[test]
	fn alive2_codec() {
		test_codec(
			&hex!["
				3292446c90740900
				0900
					0a00020f
					c0a8015b
					bbbe
					0050f21f6453
					0a00006400010000010000000000000000000000
				82bb78b11ec1da05
				39376321974612e22d1225f8c6f9c6cc
				00000000
				00000000
					0000
					0000
					0000
					0000
				0000feff
				00000000
				00000000
				00000000
				0000
				0000000000000000
				0000000000000000
			"], Alive2 {
				user_id: Xuid(0x000974906c449232),
				acct_name_len: 9,
				xnaddr: Addr {
					addr: InAddr([10, 0, 2, 15]),
					addr_online: InAddr([192, 168, 1, 91]),
					port_online: 0xbebb,
					enet: Eui48(hex!["00 50 f2 1f 64 53"]),
					online: hex!["0a000064 00010000 01000000 00000000 00000000"],
				},
				xnkid: KeyId(hex!["82bb78b11ec1da05"]),
				xnkey: SymmetricKey(hex!["39376321974612e22d1225f8c6f9c6cc"]),
				buddy_list_version: 0,
				block_list_version: 0,
				client_version: LibraryVersion {
					major: 0,
					minor: 0,
					build: 0,
					qfe: 0,
				},
				title_id: 0xfffe0000,
				title_version: 0,
				title_region: 0,
				ip_al: InAddr([0, 0, 0, 0]),
				port: 0,
				nonce: SgNonce(hex!["0000000000000000"]),
				time_init: TimeStamp(0),
			}
		)
	}

	#[test]
	fn alive_reply_codec() {
		test_codec(
			&hex!["
				56465465
				63256347
				5891
				76170867
				5018
			"], AliveReply {
				hr: HResult(0x65544656),
				buddy_list_version: 0x47632563,
				buddies_sent: 0x9158,
				block_list_version: 0x67081776,
				blocks_sent: 0x1850,
			})
	}

	const EMPTY_ALIVE_2_MSG: Alive2 = Alive2 {
		user_id: Xuid(0),
		acct_name_len: 0,
		xnaddr: Addr {
			addr: InAddr([0;4]),
			addr_online: InAddr([0;4]),
			port_online: 0,
			enet: Eui48([0;6]),
			online: [0;20],
		},
		xnkid: KeyId([0;KEY_ID_LENGTH]),
		xnkey: SymmetricKey([0;SYMMETRIC_KEY_LEN]),
		block_list_version: 0,
		buddy_list_version: 0,
		client_version: LibraryVersion {
			major: 0,
			minor: 0,
			build: 0,
			qfe: 0,
		},
		title_id: 0,
		title_version: 0,
		title_region: 0,
		port: 0,
		ip_al: InAddr([0;4]),
		nonce: SgNonce([0;SG_NONCE_LEN]),
		time_init: TimeStamp(0),
	};

	#[test]
	fn alive_reply_encode() {
		let kind = MessageKind::AliveReply(AliveReply {
			hr: HResult(0x65544656),
			buddy_list_version: 0x47632563,
			buddies_sent: 0,
			block_list_version: 0x67081776,
			blocks_sent: 0,
		});

		let req = Message {
			header: Header {
				msg_type: ALIVE_2_MSG_TYPE,
				msg_len: 0,
				seq_num: 1,
				sgaddr: SgAddr {
					ina_sg: InAddr([6, 7, 8, 9]),
					spi_sg: 99,
					xbox_id: Xuid(42),
					_rsvd_10: [0;4],
				}
			},
			kind: MessageKind::Alive2 {
				body: EMPTY_ALIVE_2_MSG,
				acct_name: "".to_owned(),
			},
		};

		let reply_msg = Message::reply_from_kind_and_req(kind, &req);

		let mut buf = vec![];

		reply_msg.put(&mut buf);

		assert_eq!(buf.as_slice(), &hex!["
			4d 04 00 00 10 00 00 00 01 00 00 00 06 07 08 09
			63 00 00 00 2a 00 00 00 00 00 00 00 00 00 00 00

			56465465
			63256347
			0000
			76170867
			0000
		"])
	}
}
