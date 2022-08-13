use bytes::BufMut;

use nom::multi::count;
use nom::number::complete::{le_i64, le_u16, le_u32, le_u8};

use std::mem::size_of;
use std::num::NonZeroUsize;

use xbox_sys::codec::{BufPut, Decode, parse_nul_terminated_ascii};
use xbox_sys::crypto::SymmetricKey;

use crate::addr::Addr;
use crate::crypto::primitives::KeyId;

pub const CONTENT_TYPE: &'static str = "xon/6";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Search {
	pub header: SearchHeader,
	pub attributes: Vec<SearchAttribute>,
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for Search {
	fn put(&self, buf: &mut AnyBufMut) {
		self.header.put(buf);
		put_attribute_block(buf, SEARCH_HEADER_SIZE, &self.attributes)
	}
}

impl Decode for Search {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, header) = SearchHeader::decode(input)?;
		let (input, attributes) = decode_attributes(
			input,
			header.num_attributes as usize,
			SEARCH_HEADER_SIZE,
			header.total_length as usize)?;

		Ok((input, Search {
			header,
			attributes,
		}))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchHeader {
	pub total_length: u32,
	pub title_id: u32,
	pub procedure_index: u32,
	pub client_address: Addr,
	pub num_users: u16,
	pub flags: u16,
	pub num_attributes: u32,
}

const SEARCH_HEADER_SIZE: usize = 56;

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for SearchHeader {
	fn put(&self, buf: &mut AnyBufMut) {
		buf.put_u32_le(self.total_length);
		buf.put_u32_le(self.title_id);
		buf.put_u32_le(self.procedure_index);
		self.client_address.put(buf);
		buf.put_u16_le(self.num_users);
		buf.put_u16_le(self.flags);
		buf.put_u32_le(self.num_attributes);
	}
}

impl Decode for SearchHeader {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, total_length) = le_u32(input)?;
		let (input, title_id) = le_u32(input)?;
		let (input, procedure_index) = le_u32(input)?;
		let (input, client_address) = Addr::decode(input)?;
		let (input, num_users) = le_u16(input)?;
		let (input, flags) = le_u16(input)?;
		let (input, num_attributes) = le_u32(input)?;

		Ok((input, SearchHeader {
			total_length,
			title_id,
			procedure_index,
			client_address,
			num_users,
			flags,
			num_attributes,
		}))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchAttribute {
	pub tag: u16,
	pub kind: SearchAttributeKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchAttributeKind {
	Null,
	Integer(i64),
	String(String),
	Unknown(Vec<u8>),
}

const SEARCH_ATTRIBUTE_TYPE_LEN: usize = size_of::<u32>();

const NUL_TERMINATOR_LEN: usize = 1;

const INTEGER_TYPE_NUM: u32 = 0x00000000;
const STRING_TYPE_NUM:  u32 = 0x00100000;
const NULL_TYPE_NUM:    u32 = 0x00F00000;

const TYPE_MASK: u32 = 0x00F00000;
const TAG_MASK:  u32 = 0x0000FFFF;

impl SearchAttribute {
	pub fn encoded_len(&self) -> usize {
		use SearchAttributeKind::*;

		match &self.kind {
			Null => SEARCH_ATTRIBUTE_TYPE_LEN,
			Integer(_) => SEARCH_ATTRIBUTE_TYPE_LEN + size_of::<i64>(),
			String(s) => SEARCH_ATTRIBUTE_TYPE_LEN + size_of::<u16>() + s.as_bytes().len() + NUL_TERMINATOR_LEN,
			Unknown(ref buf) => buf.len(),
		}
	}

	fn unknown_attribute_type(input: &[u8]) -> SearchAttribute {
		SearchAttribute {
			tag: 0,
			kind: SearchAttributeKind::Unknown(input.to_vec()),
		}
	}
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for SearchAttribute {
	fn put(&self, buf: &mut AnyBufMut) {
		use SearchAttributeKind::*;

		match &self.kind {
			Null => buf.put_u32_le(NULL_TYPE_NUM | self.tag as u32),
			Integer(i) => {
				buf.put_u32_le(INTEGER_TYPE_NUM | self.tag as u32);
				buf.put_i64_le(*i);
			}
			String(s) => {
				buf.put_u32_le(STRING_TYPE_NUM | self.tag as u32);
				buf.put_u16_le((s.as_bytes().len() + 1) as u16);
				buf.put(s.as_bytes());
				buf.put_u8(b'\0');
			}
			Unknown(bytes) => buf.put(bytes.as_slice()),
		}
	}
}

impl Decode for SearchAttribute {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let orig_input = input;
		let header_result: Result<(&'a [u8], u32), nom::Err<nom::error::Error<&'a [u8]>>> = le_u32(input);
		let (input, header) = match header_result {
			Ok((input, header)) => (input, header),
			Err(_) => return Ok((&[], Self::unknown_attribute_type(orig_input))),
		};

		let header_type = header & TYPE_MASK;
		let tag = (header & TAG_MASK) as u16;

		let kind = match header_type {
			INTEGER_TYPE_NUM => {
				if input.len() != size_of::<i64>() {
					return Ok((&[], Self::unknown_attribute_type(orig_input)))
				}
				let (_, i) = le_i64(input)?;
				SearchAttributeKind::Integer(i)
			}
			STRING_TYPE_NUM => {
				if input.len() < 2 {
					return Ok((&[], Self::unknown_attribute_type(orig_input)))
				}
				let (rem, len) = le_u16(input)?;
				let len = len as usize;
				if rem.len() != len {
					return Ok((&[], Self::unknown_attribute_type(orig_input)))
				}
				let s = match parse_nul_terminated_ascii(rem) {
					Err(_) => return Ok((&[], Self::unknown_attribute_type(orig_input))),
					Ok((_, s)) => String::from(s),
				};
				SearchAttributeKind::String(s)
			}
			NULL_TYPE_NUM => {
				if input.len() != 0 {
					return Ok((&[], Self::unknown_attribute_type(orig_input)))
				}
				SearchAttributeKind::Null
			}
			_ => {
				return Ok((&[], Self::unknown_attribute_type(orig_input)))
			}
		};

		Ok((&[], SearchAttribute {
			tag,
			kind,
		}))
	}
}

fn put_attribute_block<AnyBufMut: BufMut>(buf: &mut AnyBufMut, base: usize, attributes: &[SearchAttribute]) {
	let mut cur_base = base + (size_of::<u32>() * attributes.len());
	for attr in attributes.iter() {
		buf.put_u32_le(cur_base as u32);
		cur_base += attr.encoded_len();
	}
	for attr in attributes.iter() {
		attr.put(buf);
	}
}

fn decode_attributes<'a>(input: &'a [u8], num_attributes: usize, base: usize, total_length: usize) -> nom::IResult<&'a [u8], Vec<SearchAttribute>> {
	let attribute_buffer_start = base + size_of::<u32>() * num_attributes;
	let (input, attribute_offsets) = count(le_u32, num_attributes)(input)?;
	let attribute_buffer_len = total_length - attribute_buffer_start;
	let attr_buffer = &input[..attribute_buffer_len];
	//TODO: change count to take
	let (input, _) = count(le_u8, attribute_buffer_len)(input)?;
	let mut ends = attribute_offsets[1..].to_owned();
	ends.push(total_length as u32);

	let mut attributes = vec![];
	for (start, end) in attribute_offsets.iter().zip(ends) {
		let attr_start = *start as usize - attribute_buffer_start;
		let attr_end = end as usize - attribute_buffer_start;
		let buf = &attr_buffer[attr_start..attr_end];
		let (_, attr) = SearchAttribute::decode(buf)?;
		attributes.push(attr);
	}

	Ok((input, attributes))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
	pub header: SessionHeader,
	pub attributes: Vec<SearchAttribute>,
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for Session {
	fn put(&self, buf: &mut AnyBufMut) {
		self.header.put(buf);
		put_attribute_block(buf, SESSION_HEADER_SIZE, &self.attributes);
	}
}

impl Decode for Session {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, header) = SessionHeader::decode(input)?;
		let (input, attributes) = decode_attributes(
			input,
			header.num_attributes as usize,
			SESSION_HEADER_SIZE,
			header.total_length as usize)?;

		Ok((input, Session {
			header,
			attributes,
		}))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
	pub session_id: KeyId,
	pub key_exchange_key: SymmetricKey,
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for SessionInfo {
	fn put(&self, buf: &mut AnyBufMut) {
		self.session_id.put(buf);
		self.key_exchange_key.put(buf);
	}
}

impl Decode for SessionInfo {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, session_id) = KeyId::decode(input)?;
		let (input, key_exchange_key) = SymmetricKey::decode(input)?;

		Ok((input, SessionInfo {
			session_id,
			key_exchange_key,
		}))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionHeader {
	pub total_length: u32,
	pub session_id: KeyId,
	pub title_id: u32,
	pub host_address: Addr,
	pub public_open: u32,
	pub private_open: u32,
	pub public_filled: u32,
	pub private_filled: u32,
	pub num_attributes: u32,
}

const SESSION_HEADER_SIZE: usize = 72;

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for SessionHeader {
	fn put(&self, buf: &mut AnyBufMut) {
		buf.put_u32_le(self.total_length);
		self.session_id.put(buf);
		buf.put_u32_le(self.title_id);
		self.host_address.put(buf);
		buf.put_u32_le(self.public_open);
		buf.put_u32_le(self.private_open);
		buf.put_u32_le(self.public_filled);
		buf.put_u32_le(self.private_filled);
		buf.put_u32_le(self.num_attributes);
	}
}

impl Decode for SessionHeader {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, total_length) = le_u32(input)?;
		let (input, session_id) = KeyId::decode(input)?;
		let (input, title_id) = le_u32(input)?;
		let (input, host_address) = Addr::decode(input)?;
		let (input, public_open) = le_u32(input)?;
		let (input, private_open) = le_u32(input)?;
		let (input, public_filled) = le_u32(input)?;
		let (input, private_filled) = le_u32(input)?;
		let (input, num_attributes) = le_u32(input)?;

		Ok((input, SessionHeader {
			total_length,
			session_id,
			title_id,
			host_address,
			public_open,
			private_open,
			public_filled,
			private_filled,
			num_attributes,
		}))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResults {
	pub header: SearchResultsHeader,
	pub results: Vec<SearchResult>,
}

impl SearchResults {
	pub fn generate(flags: u16, logging_threshold: u32, results: Vec<SearchResult>) -> Self {
		let mut message_length = 0;
		for result in results.iter() {
			message_length += result.header.result_length as usize;
		}
		message_length += SearchResultsHeader::ENCODED_LEN;

		SearchResults {
			header: SearchResultsHeader {
				message_length: message_length as u32,
				num_search_results: results.len() as u16,
				flags,
				logging_threshold,
			},
			results
		}
	}
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for SearchResults {
	fn put(&self, buf: &mut AnyBufMut) {
		self.header.put(buf);
		for result in self.results.iter() {
			result.put(buf);
		}
	}
}

impl Decode for SearchResults {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let orig_input = input;
		let (_input, header) = SearchResultsHeader::decode(input)?;

		let message_len = header.message_length as usize;

		if message_len < SearchResultsHeader::ENCODED_LEN {
			return Err(nom::Err::Error(nom::error::Error {
				input: orig_input,
				code: nom::error::ErrorKind::LengthValue,
			}))
		}

		if orig_input.len() < message_len {
			return Err(nom::Err::Incomplete(nom::Needed::Size(NonZeroUsize::new(message_len).unwrap())))
		}

		let mut results_input = &orig_input[SearchResultsHeader::ENCODED_LEN..message_len];
		let mut results = vec![];
		for _ in 0..header.num_search_results {
			let (rem, result) = SearchResult::decode(results_input)?;
			results.push(result);
			results_input = rem;
		}

		Ok((&orig_input[message_len..], SearchResults {
			header,
			results,
		}))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResultsHeader {
	pub message_length: u32,
	pub num_search_results: u16,
	pub flags: u16,
	pub logging_threshold: u32,
}

impl SearchResultsHeader {
	pub const ENCODED_LEN: usize = 4 + 2 + 2 + 4;
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for SearchResultsHeader {
	fn put(&self, buf: &mut AnyBufMut) {
		buf.put_u32_le(self.message_length);
		buf.put_u16_le(self.num_search_results);
		buf.put_u16_le(self.flags);
		buf.put_u32_le(self.logging_threshold);
	}
}

impl Decode for SearchResultsHeader {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, message_length) = le_u32(input)?;
		let (input, num_search_results) = le_u16(input)?;
		let (input, flags) = le_u16(input)?;
		let (input, logging_threshold) = le_u32(input)?;

		Ok((input, SearchResultsHeader {
			message_length,
			num_search_results,
			flags,
			logging_threshold,
		}))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResult {
	pub header: SearchResultHeader,
	pub attributes: Vec<SearchAttribute>,
}

impl SearchResult {
	pub fn generate(session_id: KeyId, host_address: Addr, key_exchange_key: SymmetricKey, public_open: u32, private_open: u32, public_filled: u32, private_filled: u32, attributes: Vec<SearchAttribute>) -> Self {
		let mut attribute_len = 0;
		for attr in attributes.iter() {
			attribute_len += attr.encoded_len() + 4;
		}

		let total_len = attribute_len + SearchResultHeader::ENCODED_LEN;

		SearchResult {
			header: SearchResultHeader {
				result_length: total_len as u32,
				session_id,
				host_address,
				key_exchange_key,
				public_open,
				private_open,
				public_filled,
				private_filled,
				num_attributes: attributes.len() as u32
			},
			attributes
		}
	}
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for SearchResult {
	fn put(&self, buf: &mut AnyBufMut) {
		self.header.put(buf);
		put_attribute_block(buf, SearchResultHeader::ENCODED_LEN, &self.attributes)
	}
}

impl Decode for SearchResult {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, header) = SearchResultHeader::decode(input)?;
		let (input, attributes) = decode_attributes(
			input,
			header.num_attributes as usize,
			SearchResultHeader::ENCODED_LEN,
			header.result_length as usize)?;

		Ok((input, SearchResult {
			header,
			attributes,
		}))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResultHeader {
	pub result_length: u32,
	pub session_id: KeyId,
	pub host_address: Addr,
	pub key_exchange_key: SymmetricKey,
	pub public_open: u32,
	pub private_open: u32,
	pub public_filled: u32,
	pub private_filled: u32,
	pub num_attributes: u32,
}

impl SearchResultHeader {
	pub const ENCODED_LEN: usize = 4 + 8 + Addr::ENCODED_LEN + 16 + 4 + 4 + 4 + 4 + 4;
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for SearchResultHeader {
	fn put(&self, buf: &mut AnyBufMut) {
		buf.put_u32_le(self.result_length);
		self.session_id.put(buf);
		self.host_address.put(buf);
		self.key_exchange_key.put(buf);
		buf.put_u32_le(self.public_open);
		buf.put_u32_le(self.private_open);
		buf.put_u32_le(self.public_filled);
		buf.put_u32_le(self.private_filled);
		buf.put_u32_le(self.num_attributes);
	}
}

impl Decode for SearchResultHeader {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, result_length) = le_u32(input)?;
		let (input, session_id) = KeyId::decode(input)?;
		let (input, host_address) = Addr::decode(input)?;
		let (input, key_exchange_key) = SymmetricKey::decode(input)?;
		let (input, public_open) = le_u32(input)?;
		let (input, private_open) = le_u32(input)?;
		let (input, public_filled) = le_u32(input)?;
		let (input, private_filled) = le_u32(input)?;
		let (input, num_attributes) = le_u32(input)?;

		Ok((input, SearchResultHeader {
			result_length,
			session_id,
			host_address,
			key_exchange_key,
			public_open,
			private_open,
			public_filled,
			private_filled,
			num_attributes,
		}))
	}
}

#[cfg(test)]
mod tests {
	use hex_literal::hex;

	use xbox_sys::codec::test_codec;
	use crate::net::{InAddr, Eui48};

	use super::*;

	#[test]
	fn null_attribute_codec() {
		test_codec(&hex!["
			67 45 f0 00
		"], SearchAttribute {
			tag: 0x4567,
			kind: SearchAttributeKind::Null,
		})
	}

	#[test]
	fn integer_attribute_codec() {
		test_codec(&hex!["
			de ab 00 00 ef cd ab 89 67 45 23 01
		"], SearchAttribute {
			tag: 0xabde,
			kind: SearchAttributeKind::Integer(0x0123456789abcdef),
		})
	}

	#[test]
	fn string_attribute_codec() {
		test_codec(&hex!["
			03 00 10 00 09 00 6d 6f 6e 6f 63 61 73 61 00
		"], SearchAttribute {
			tag: 3,
			kind: SearchAttributeKind::String(String::from("monocasa")),
		})
	}

	#[test]
	fn search_codec() {
		test_codec(&hex!["
			88 00 00 00
			0b 00 41 4c
			01 00 00 00
				0a 00 02 0f
				c0 a8 01 5b
				90 73
				00 50 f2 1f 64 53
				0a 00 00 64 00 02 00 00 01 00 00 00 00 00 00 00 00 00 00 00
			
			01 00 
			00 00
			08 00 00 00 
			
			58 00 00 00
			5c 00 00 00
			60 00 00 00
			6c 00 00 00
			78 00 00 00
			7c 00 00 00
			80 00 00 00
			84 00 00 00
			
			00 00 f0 00
			00 00 f0 00
			00 00 00 00 00 00 00 00 00 00 00 00
			00 00 00 00 08 00 00 00 00 00 00 00
			00 00 f0 00
			00 00 f0 00
			00 00 f0 00
			00 00 f0 00
		"], Search {
			header: SearchHeader {
				total_length: 136,
				title_id: 0x4c41000b,
				procedure_index: 1,
				client_address: Addr {
					addr: InAddr([10, 0, 2, 15]),
					addr_online: InAddr([192, 168, 1, 91]),
					port_online: 0x7390,
					enet: Eui48(hex!["00 50 f2 1f 64 53"]),
					online: hex!["0a 00 00 64 00 02 00 00 01 00 00 00 00 00 00 00 00 00 00 00"],
				},
				num_users: 1,
				flags: 0,
				num_attributes: 8
			},
			attributes: vec![
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Integer(0) },
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Integer(8) },
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
			]
		})
	}

	#[test]
	fn search_header_codec() {
		test_codec(&hex!["
			88 00 00 00
			0b 00 41 4c
			01 00 00 00
				0a 00 02 0f
				c0 a8 01 5b
				90 73
				00 50 f2 1f 64 53
				0a 00 00 64 00 02 00 00 01 00 00 00 00 00 00 00 00 00 00 00
			
			01 00 
			00 00
			08 00 00 00 
		"], SearchHeader {
			total_length: 136,
			title_id: 0x4c41000b,
			procedure_index: 1,
			client_address: Addr {
				addr: InAddr([10, 0, 2, 15]),
				addr_online: InAddr([192, 168, 1, 91]),
				port_online: 0x7390,
				enet: Eui48(hex!["00 50 f2 1f 64 53"]),
				online: hex!["0a 00 00 64 00 02 00 00 01 00 00 00 00 00 00 00 00 00 00 00"],
			},
			num_users: 1,
			flags: 0,
			num_attributes: 8
		})
	}

	#[test]
	fn session_codec() {
		test_codec(&hex!["
			cb 00 00 00
			00 00 00 00 00 00 00 00
			0b 00 41 4c

			0a 00 02 0f
			c0 a8 01 5b c7 25 00 50 f2 1f 64 53 0a 00 00 64
			00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00
			07 00 00 00
			00 00 00 00
			01 00 00 00
			00 00 00 00
			08 00 00 00

			68 00 00 00
			74 00 00 00
			80 00 00 00
			8f 00 00 00
			9b 00 00 00
			a7 00 00 00
			b3 00 00 00
			bf 00 00 00

			01 00 00 00 00 00 00 00 00 00 00 00
			02 00 00 00 0f 00 00 00 00 00 00 00
			03 00 10 00 09 00 6d 6f 6e 6f 63 61 73 61 00
			04 00 00 00 00 00 00 00 00 00 00 00
			05 00 00 00 07 00 00 00 00 00 00 00
			07 00 00 00 01 00 00 00 00 00 00 00
			08 00 00 00 00 00 00 00 00 00 00 00
			09 00 00 00 00 00 00 00 00 00 00 00
		"], Session {
			header: SessionHeader {
				total_length: 203,
				session_id: KeyId(hex!["00 00 00 00 00 00 00 00"]),
				title_id: 0x4c41000b,
				host_address: Addr {
					addr: InAddr([10, 0, 2, 15]),
					addr_online: InAddr([192, 168, 1, 91]),
					port_online: 0x25c7,
					enet: Eui48(hex!["00 50 f2 1f 64 53"]),
					online: hex!["0a 00 00 64 00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00"]
				},
				public_open: 7,
				private_open: 0,
				public_filled: 1,
				private_filled: 0,
				num_attributes: 8,
			},
			attributes: vec![
				SearchAttribute { tag: 1, kind: SearchAttributeKind::Integer(0) },
				SearchAttribute { tag: 2, kind: SearchAttributeKind::Integer(15) },
				SearchAttribute { tag: 3, kind: SearchAttributeKind::String(String::from("monocasa")) },
				SearchAttribute { tag: 4, kind: SearchAttributeKind::Integer(0)},
				SearchAttribute { tag: 5, kind: SearchAttributeKind::Integer(7) },
				SearchAttribute { tag: 7, kind: SearchAttributeKind::Integer(1) },
				SearchAttribute { tag: 8, kind: SearchAttributeKind::Integer(0) },
				SearchAttribute { tag: 9, kind: SearchAttributeKind::Integer(0) },
			],
		})
	}

	#[test]
	fn session_header_codec() {
		test_codec(&hex!["
			cb 00 00 00
			00 00 00 00 00 00 00 00
			0b 00 41 4c

			0a 00 02 0f
			c0 a8 01 5b c7 25 00 50 f2 1f 64 53 0a 00 00 64
			00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00
			07 00 00 00
			00 00 00 00
			01 00 00 00
			00 00 00 00
			08 00 00 00
		"], SessionHeader {
			total_length: 203,
			session_id: KeyId(hex!["00 00 00 00 00 00 00 00"]),
			title_id: 0x4c41000b,
			host_address: Addr {
				addr: InAddr([10, 0, 2, 15]),
				addr_online: InAddr([192, 168, 1, 91]),
				port_online: 0x25c7,
				enet: Eui48(hex!["00 50 f2 1f 64 53"]),
				online: hex!["0a 00 00 64 00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00"]
			},
			public_open: 7,
			private_open: 0,
			public_filled: 1,
			private_filled: 0,
			num_attributes: 8,
		})
	}

	#[test]
	fn search_results_codec() {
		test_codec(&hex!["
			d4 00 00 00
			02 00
			12 34
			56 78 90 12

			64 00 00 00
			00 11 22 33 44 55 66 77

			0a 00 02 0f
			c0 a8 01 5b c7 25 00 50 f2 1f 64 53 0a 00 00 64
			00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00

			01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef
			01 00 00 00
			02 00 00 00
			03 00 00 00
			04 00 00 00
			02 00 00 00

			5c 00 00 00
			60 00 00 00

			00 00 f0 00
			00 00 f0 00

			64 00 00 00
			01 23 45 67 89 ab cd ef

			0a 00 02 0f
			c0 a8 01 5b c7 25 00 50 f2 1f 64 53 0a 00 00 64
			00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00

			00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
			01 00 00 00
			02 00 00 00
			03 00 00 00
			04 00 00 00
			02 00 00 00

			5c 00 00 00
			60 00 00 00

			00 00 f0 00
			00 00 f0 00
		"], SearchResults {
			header: SearchResultsHeader {
				message_length: 212,
				num_search_results: 2,
				flags: 0x3412,
				logging_threshold: 0x12907856,
			},
			results: vec![
				SearchResult {
					header: SearchResultHeader {
						result_length: 100,
						session_id: KeyId(hex!["00 11 22 33 44 55 66 77"]),
						host_address: Addr {
							addr: InAddr([10, 0, 2, 15]),
							addr_online: InAddr([192, 168, 1, 91]),
							port_online: 0x25c7,
							enet: Eui48(hex!["00 50 f2 1f 64 53"]),
							online: hex!["0a 00 00 64 00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00"]
						},
						key_exchange_key: SymmetricKey(hex!["01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef"]),
						public_open: 1,
						private_open: 2,
						public_filled: 3,
						private_filled: 4,
						num_attributes: 2
					},
					attributes: vec![
						SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
						SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
					]
				},
				SearchResult {
					header: SearchResultHeader {
						result_length: 100,
						session_id: KeyId(hex!["01 23 45 67 89 ab cd ef"]),
						host_address: Addr {
							addr: InAddr([10, 0, 2, 15]),
							addr_online: InAddr([192, 168, 1, 91]),
							port_online: 0x25c7,
							enet: Eui48(hex!["00 50 f2 1f 64 53"]),
							online: hex!["0a 00 00 64 00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00"]
						},
						key_exchange_key: SymmetricKey(hex!["00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"]),
						public_open: 1,
						private_open: 2,
						public_filled: 3,
						private_filled: 4,
						num_attributes: 2
					},
					attributes: vec![
						SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
						SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
					]
				},
			]
		})
	}

	#[test]
	fn search_results_header_codec() {
		test_codec(&hex!["
			12 34 56 78
			90 12
			34 56
			78 90 12 34
		"], SearchResultsHeader {
			message_length: 0x78563412,
			num_search_results: 0x1290,
			flags: 0x5634,
			logging_threshold: 0x34129078,
		})
	}

	#[test]
	fn search_result_codec() {
		test_codec(&hex!["
			64 00 00 00
			01 23 45 67 89 ab cd ef

			0a 00 02 0f
			c0 a8 01 5b c7 25 00 50 f2 1f 64 53 0a 00 00 64
			00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00

			00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
			01 00 00 00
			02 00 00 00
			03 00 00 00
			04 00 00 00
			02 00 00 00

			5c 00 00 00
			60 00 00 00

			00 00 f0 00
			00 00 f0 00
		"], SearchResult {
			header: SearchResultHeader {
				result_length: 100,
				session_id: KeyId(hex!["01 23 45 67 89 ab cd ef"]),
				host_address: Addr {
					addr: InAddr([10, 0, 2, 15]),
					addr_online: InAddr([192, 168, 1, 91]),
					port_online: 0x25c7,
					enet: Eui48(hex!["00 50 f2 1f 64 53"]),
					online: hex!["0a 00 00 64 00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00"]
				},
				key_exchange_key: SymmetricKey(hex!["00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"]),
				public_open: 1,
				private_open: 2,
				public_filled: 3,
				private_filled: 4,
				num_attributes: 2
			},
			attributes: vec![
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
			]
		})
	}

	#[test]
	fn generating_search_result() {
		assert_eq!(SearchResult::generate(
			KeyId(hex!["01 23 45 67 89 ab cd ef"]),
			Addr {
				addr: InAddr([10, 0, 2, 15]),
				addr_online: InAddr([192, 168, 1, 91]),
				port_online: 0x25c7,
				enet: Eui48(hex!["00 50 f2 1f 64 53"]),
				online: hex!["0a 00 00 64 00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00"]
			},
			SymmetricKey(hex!["00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"]),
			1,
			2,
			3,
			4,
			vec![
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
			]
		), SearchResult {
			header: SearchResultHeader {
				result_length: 100,
				session_id: KeyId(hex!["01 23 45 67 89 ab cd ef"]),
				host_address: Addr {
					addr: InAddr([10, 0, 2, 15]),
					addr_online: InAddr([192, 168, 1, 91]),
					port_online: 0x25c7,
					enet: Eui48(hex!["00 50 f2 1f 64 53"]),
					online: hex!["0a 00 00 64 00 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00"]
				},
				key_exchange_key: SymmetricKey(hex!["00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"]),
				public_open: 1,
				private_open: 2,
				public_filled: 3,
				private_filled: 4,
				num_attributes: 2
			},
			attributes: vec![
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
				SearchAttribute { tag: 0, kind: SearchAttributeKind::Null },
			]
		})
	}
}
