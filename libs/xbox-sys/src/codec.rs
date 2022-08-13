use bytes::BufMut;
#[cfg(feature = "std")]
use bytes::BytesMut;

use core::str::from_utf8;

use nom::{Needed, AsBytes};
use nom::number::complete::{le_u16, le_u8};

#[cfg(feature = "std")]
use std::borrow::Borrow;
#[cfg(feature = "std")]
use std::fmt::Debug;

pub trait BufPut<AnyBufMut: BufMut> {
	fn put(&self, buf: &mut AnyBufMut);
}

pub trait Decode
where
	Self: Sized
{
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self>;
}

pub fn decode_array_u8<'a, const N: usize>(input: &'a [u8]) -> nom::IResult<&'a [u8], [u8;N]> {
	let mut arr = [0;N];
	let mut rem = input;
	for i in 0..N {
		let (new_rem, value) = le_u8(rem)?;
		rem = new_rem;
		arr[i] = value;
	}
	Ok((rem, arr))
}

pub fn decode_array_le_u16<'a, const N: usize>(input: &'a [u8]) -> nom::IResult<&'a [u8], [u16;N]> {
	let mut arr = [0;N];
	let mut rem = input;
	for i in 0..N {
		let (new_rem, value) = le_u16(rem)?;
		rem = new_rem;
		arr[i] = value;
	}
	Ok((rem, arr))
}

pub fn parse_nul_terminated_ascii<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], &'a str> {
	let bytes = input.as_bytes();
	let mut nul_offset = None;
	for i in 0..input.len() {
		if bytes[i] & 0b_1000_0000 != 0 {
			return Err(nom::Err::Error(nom::error::Error {
				input: &bytes[i..],
				code: nom::error::ErrorKind::IsNot,
			}))
		}
		if bytes[i] == b'\0' {
			nul_offset = Some(i);
			break;
		}
	}
	let nul_offset = nul_offset.ok_or(nom::Err::Incomplete(Needed::Unknown))?;
	let next = nul_offset + 1;
	let input = &bytes[next..];
	let s = from_utf8(&bytes[..nul_offset]).unwrap();
	Ok((input, s))
}

pub fn put_nul_terminated_ascii<AnyBufMut: BufMut>(s: &str, buf: &mut AnyBufMut) {
	buf.put_slice(s.as_bytes());
	buf.put_u8(b'\0');
}

#[cfg(feature = "std")]
pub fn test_codec<'a, StructUnderTest>(bytes: &'a [u8], s: StructUnderTest)
where
	StructUnderTest: BufPut<BytesMut> + Debug + PartialEq + Decode,
{
	let mut generated_bytes = BytesMut::with_capacity(bytes.len());

	s.put(&mut generated_bytes);

	assert_eq!(bytes, generated_bytes.as_ref());

	let (remainder, generated_s) = StructUnderTest::decode(generated_bytes.borrow()).unwrap();

	assert!(remainder.len() == 0);

	assert_eq!(s, generated_s);
}


#[cfg(test)]
mod tests {
	use hex_literal::hex;

	use super::*;

	#[test]
	fn parse_nul_terminated_ascii_good() {
		assert_eq!(
			parse_nul_terminated_ascii(&hex!["41 43 41 42 00"]),
			Ok(([].as_slice(), "ACAB")),
		)
	}

	#[test]
	fn parse_nul_terminated_ascii_bad_zero_size_slice() {
		assert_eq!(
			parse_nul_terminated_ascii(&[]),
			Err(nom::Err::Incomplete(Needed::Unknown)),
		)
	}

	#[test]
	fn parse_nul_terminated_ascii_bad_unterminated() {
		assert_eq!(
			parse_nul_terminated_ascii(&[0x41]),
			Err(nom::Err::Incomplete(Needed::Unknown)),
		)
	}

	#[test]
	fn parse_nul_terminated_ascii_bad_non_ascii() {
		assert_eq!(
			parse_nul_terminated_ascii(&[0x41, 0x90]),
			Err(nom::Err::Error(nom::error::Error::<&[u8]> {
				input: &[0x90],
				code: nom::error::ErrorKind::IsNot,
			}))
		)
	}

	#[test]
	fn put_nul_terminated_ascii_good() {
		let mut buf = vec![];

		put_nul_terminated_ascii("test string", &mut buf);

		assert_eq!(b"test string\0", buf.as_slice())
	}
}