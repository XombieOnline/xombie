use core::{mem::size_of, convert::{TryInto, TryFrom}};

use nom::number::complete::le_u32;

use crate::codec::Decode;
use crate::crypto::DesIv;

pub const CONFIG_AREA_SECTOR_BASE: u64 = 8;
pub const CONFIG_PARAMS_SECTOR:    u64 = CONFIG_AREA_SECTOR_BASE + 0;
pub const MACHINE_ACCOUNT_SECTOR:  u64 = CONFIG_AREA_SECTOR_BASE + 1;
pub const USER_TABLE_SECTOR:       u64 = CONFIG_AREA_SECTOR_BASE + 3;
pub const FIRST_USER_SECTOR:       u64 = CONFIG_AREA_SECTOR_BASE + 4;
pub const NUM_USER_SECTORS: usize = 8;

pub const SECTOR_LEN: usize = 512;

pub const HEADER_WORD:      usize = 0;
pub const NONZERO_WORD_004: usize = 1;
pub const NONZERO_WORD_008: usize = 2;
pub const CHECKSUM_WORD:    usize = 126;
pub const FOOTER_WORD:      usize = 127;

pub const PAYLOAD_START_BYTE: usize = 0x00C;
pub const PAYLOAD_END_BYTE:   usize = 0x1F8;

pub const MAX_PAYLOAD_LEN: usize = PAYLOAD_END_BYTE - PAYLOAD_START_BYTE;

pub const NUM_WORDS: usize = SECTOR_LEN / size_of::<u32>();

pub const HEADER_MAGIC: u32 = 0x79132568;
pub const FOOTER_MAGIC: u32 = 0xaa550000;

#[derive(Debug)]
pub struct Sector(pub [u8;SECTOR_LEN]);

impl Default for Sector {
	fn default() -> Self {
		Sector([0u8;SECTOR_LEN])
	}
}

impl Sector {
	pub fn word(&self, word_num: usize) -> u32 {
		let offset = word_num * size_of::<u32>();
		let end = offset + size_of::<u32>();
		let bytes = &self.0[offset..end];
		u32::from_le_bytes(bytes.try_into().unwrap())
	}

	pub fn word_iter<'a>(&'a self) -> WordIter<'a> {
		WordIter {
			sector: self,
			base: 0,
		}
	}

	pub fn set_word(&mut self, word_num: usize, value: u32) {
		let offset = word_num * size_of::<u32>();
		let end = offset + size_of::<u32>();
		let bytes = &mut self.0[offset..end];
		bytes.copy_from_slice(&value.to_le_bytes())
	}

	pub fn checksum(&self) -> u32 {
		let mut acc: u64 = 0;
	
		for (word_num, word) in self.word_iter().enumerate() {
			if word_num != CHECKSUM_WORD {
				acc += word as u64
			}
		}
		acc += acc >> 32;
	
		acc as u32
	}

	pub fn payload<'a>(&'a self) -> &'a [u8] {
		&self.0[PAYLOAD_START_BYTE..PAYLOAD_END_BYTE]
	}
}

#[derive(Debug)]
pub enum SectorEncodeError {
	PayloadTooLong(usize),
}

impl TryFrom<&[u8]> for Sector {
	type Error = SectorEncodeError;

	fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
		if value.len() > MAX_PAYLOAD_LEN {
			return Err(SectorEncodeError::PayloadTooLong(value.len()))
		}

		let payload_end = PAYLOAD_START_BYTE + value.len();

		let mut sector = Sector::default();

		sector.set_word(HEADER_WORD, HEADER_MAGIC);
		sector.set_word(NONZERO_WORD_004, 1);
		sector.set_word(NONZERO_WORD_008, 1);

		sector.0[PAYLOAD_START_BYTE..payload_end].copy_from_slice(value);

		sector.set_word(FOOTER_WORD, FOOTER_MAGIC);

		let checksum = sector.checksum();

		sector.set_word(CHECKSUM_WORD, !checksum);

		Ok(sector)
	}
}

pub struct WordIter<'a> {
	sector: &'a Sector,
	base: usize,
}

impl<'a> Iterator for WordIter<'a> {
	type Item = u32;

	fn next(&mut self) -> Option<Self::Item> {
		if self.base >= NUM_WORDS {
			return None;
		}

		let word = self.sector.word(self.base);

		self.base += 1;

		Some(word)
	}
}

pub fn validate_sector<'a>(sector: &'a Sector) -> Option<&'a [u8]> {
	if sector.word(HEADER_WORD) != HEADER_MAGIC {
		return None;
	}
	if sector.word(NONZERO_WORD_004) == 0 {
		return None;
	}
	if sector.word(NONZERO_WORD_008) == 0 {
		return None;
	}
	if sector.word(FOOTER_WORD) != FOOTER_MAGIC {
		return None;
	}

	let checksum = sector.checksum();

	if sector.word(CHECKSUM_WORD) != !checksum {
		return None;
	}

	Some(sector.payload())
}

pub const MAX_USERS_IN_TABLE: usize = 8;

fn parse_user_table_entry<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Option<DesIv>> {
	let (input, valid) = le_u32(input)?;
	let (input, iv) = DesIv::decode(input)?;

	if valid != 0 {
		Ok((input, Some(iv)))
	} else {
		Ok((input, None))
	}
}

pub fn parse_user_table<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], [Option<DesIv>; MAX_USERS_IN_TABLE]> {
	let mut input = input;
	let mut table = [None;MAX_USERS_IN_TABLE];

	for i in 0..MAX_USERS_IN_TABLE {
		let (new_input, table_entry) = parse_user_table_entry(input)?;

		input = new_input;
		table[i] = table_entry;
	}

	Ok((input, table))
}

#[cfg(test)]
mod tests {
	use super::*;

	use hex_literal::hex;

	const TEST_MACHINE_ACCOUNT_SECTOR: Sector = Sector(hex!["
		68 25 13 79 01 00 00 00 01 00 00 00 01 00 00 00
		00 00 00 00 00 00 00 00 53 4e 2e 38 30 31 37 33
		35 39 39 39 32 31 36 00 00 00 00 00 00 00 00 00
		78 62 6f 78 2e 63 6f 6d 00 00 00 00 00 00 00 00
		00 00 00 00 70 61 73 73 70 6f 72 74 2e 6e 65 74
		00 00 00 00 00 00 00 00 00 00 00 00 54 89 13 ac
		ff c2 cf e0 94 60 77 38 70 6e 87 4c 00 00 00 00
		5d 94 1d 23 75 4a 53 3b 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 c7 f1 45 85 00 00 55 aa
	"]);

	#[test]
	fn test_sector_checksum() {
		assert_eq!(0x7aba0e38, TEST_MACHINE_ACCOUNT_SECTOR.checksum())
	}

	#[test]
	fn test_validate_sector() {
		assert!(validate_sector(&TEST_MACHINE_ACCOUNT_SECTOR).is_some())
	}
}
