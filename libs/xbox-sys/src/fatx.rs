use bytes::BufMut;

use nom::number::complete::le_u32;

use crate::codec::{BufPut, Decode, decode_array_u8, decode_array_le_u16};

pub const SECTOR_SIZE: usize = 512;

pub const VOLUME_HEADER_BASE_BLOCK: u64 = 0;
pub const VOLUME_HEADER_NUM_BLOCKS: usize = 5;

#[derive(Debug)]
#[repr(C)]
pub struct VolumeHeader {
	pub signature: u32,
	pub serial_number: u32,
	pub sectors_per_cluster: u32,
	pub root_directory_first_cluster: u32,
	pub volume_name: [u16;16],
	pub unknown_30: [u8;0x20],
	pub mu_online_account_buf: [u8;0x6c],
	pub unknown_bc: [u8;0x774],
}

impl Decode for VolumeHeader {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, signature) = le_u32(input)?;
		let (input, serial_number) = le_u32(input)?;
		let (input, sectors_per_cluster) = le_u32(input)?;
		let (input, root_directory_first_cluster) = le_u32(input)?;
		let (input, volume_name) = decode_array_le_u16(input)?;
		let (input, unknown_30) = decode_array_u8(input)?;
		let (input, mu_online_account_buf) = decode_array_u8(input)?;
		let (input, unknown_bc) = decode_array_u8(input)?;

		Ok((input, VolumeHeader {
			signature,
			serial_number,
			sectors_per_cluster,
			root_directory_first_cluster,
			volume_name,
			unknown_30,
			mu_online_account_buf,
			unknown_bc,
		}))
	}
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for VolumeHeader {
	fn put(&self, buf: &mut AnyBufMut) {
		buf.put_u32_le(self.signature);
		buf.put_u32_le(self.serial_number);
		buf.put_u32_le(self.sectors_per_cluster);
		buf.put_u32_le(self.root_directory_first_cluster);
		for c in self.volume_name {
			buf.put_u16_le(c)
		}
		buf.put_slice(&self.unknown_30);
		buf.put_slice(&self.mu_online_account_buf);
		buf.put_slice(&self.unknown_bc);
	}
}
