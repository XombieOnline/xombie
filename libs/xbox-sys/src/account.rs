use bytes::BufMut;

use core::convert::TryFrom;

use nom::number::complete::{le_u64, le_u32};

use crate::codec::{BufPut, Decode, decode_array_u8};

use crate::crypto::SymmetricKey;

pub const XUID_LEN: usize = 8;
pub const GAMERTAG_LEN: usize = 16;
pub const DOMAIN_LEN: usize = 20;
pub const REALM_LEN: usize = 24;
pub const KEY_LEN: usize = 16;
pub const PASSCODE_LEN: usize = 4;
pub const SIGNATURE_LEN: usize = 8;

pub const STORED_ACCOUNT_LEN: usize = 0x6c;

/// Core xbox live user id type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Xuid(pub u64);

impl Xuid {
    pub const INVALID: Xuid = Xuid(0);

	#[cfg(feature = "std")]
    pub fn build(&self) -> std::vec::Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for Xuid {
	fn put(&self, buf: &mut AnyBufMut) {
		buf.put_u64_le(self.0)
	}
}

impl Decode for Xuid {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, val) = le_u64(input)?;
		Ok((input, Xuid(val)))
	}
}

/// Wiretransfer type for gamertags
pub type Gamertag = SafeStrBuf::<GAMERTAG_LEN>;
/// Wiretransfer type for kerberos domains 
pub type Domain = SafeStrBuf::<DOMAIN_LEN>;
/// Wiretransfer type for kerberos realms
pub type Realm = SafeStrBuf::<REALM_LEN>;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PassCode(pub [u8;PASSCODE_LEN]);

impl Decode for PassCode {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, array) = decode_array_u8(input)?;
		Ok((input, PassCode(array)))
	}
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Signature(pub [u8;SIGNATURE_LEN]);

impl Decode for Signature {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, array) = decode_array_u8(input)?;
		Ok((input, Signature(array)))
	}
}

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct StoredAccount {
	pub xuid: Xuid,
	pub user_flags: u32,
	pub gamertag: Gamertag,
	pub user_options: u32,
	pub passcode: PassCode,
	pub domain: Domain,
	pub kerberos_realm: Realm,
	pub key: SymmetricKey,
	pub signature_time: u32,
	pub signature: Signature,
}

#[derive(Clone, Copy, Debug)]
pub struct UnsignedAccount {
    pub xuid: Xuid,
    pub user_flags: u32,
    pub gamertag: Gamertag,
    pub user_options: u32,
    pub passcode: PassCode,
    pub domain: Domain,
    pub kerberos_realm: Realm,
    pub key: SymmetricKey,
}

impl Decode for UnsignedAccount {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, xuid) = Xuid::decode(input)?;
        let (input, user_flags) = le_u32(input)?;
        let (input, gamertag) = Gamertag::decode(input)?;
        let (input, user_options) = le_u32(input)?;
        let (input, passcode) = PassCode::decode(input)?;
        let (input, domain) = Domain::decode(input)?;
        let (input, kerberos_realm) = Realm::decode(input)?;
        let (input, key) = SymmetricKey::decode(input)?;

        Ok((input, UnsignedAccount {
            xuid,
            user_flags,
            gamertag,
            user_options,
            passcode,
            domain,
            kerberos_realm,
            key,
        }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafeStrBuf<const N: usize>([u8;N]);

impl<const N: usize> SafeStrBuf<N> {
	pub fn bytes<'a>(&'a self) -> &'a [u8;N] {
		&self.0
	}

	pub fn char_valid(c: char) -> bool {
		match c {
			'a'..='z' => true,
			'A'..='Z' => true,
			'0'..='9' => true,
			'.' => true,
			'_' => true,
			_ => false,
		}
	}
}

impl<const N: usize> Decode for SafeStrBuf<N> {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let orig_input = input;

		let (input, buf) = decode_array_u8(input)?;

		if buf[N-1] != b'\0' {
			return Err(nom::Err::Failure(nom::error::Error::new(orig_input, nom::error::ErrorKind::Verify)))
		}
		
		Ok((input, SafeStrBuf(buf)))
	}
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SafeStrBufFromStrError {
	TooLong(usize),
	InvalidByte(u8),
}

impl<const N: usize> TryFrom<&str> for SafeStrBuf<N> {
	type Error = SafeStrBufFromStrError;

	fn try_from(s: &str) -> Result<Self, Self::Error> {
		let bytes = s.bytes();
		if bytes.len() > (N - 1)  {
			return Err(SafeStrBufFromStrError::TooLong(bytes.len()))
		}

		let mut buf = SafeStrBuf::default();

		for (i, byte) in bytes.enumerate() {
			if !Self::char_valid(byte as char) {
				return Err(SafeStrBufFromStrError::InvalidByte(byte))
			}
			buf.0[i] = byte;
		}

		Ok(buf)
	}
}

impl<const N: usize> Default for SafeStrBuf<N> {
	fn default() -> Self {
		SafeStrBuf([0u8;N])
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn stored_account_correct_size() {
		assert_eq!(108, core::mem::size_of::<StoredAccount>());
	}
}
