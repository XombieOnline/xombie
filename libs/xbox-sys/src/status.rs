use bytes::BufMut;

use nom::number::complete::le_u32;

use crate::codec::{BufPut, Decode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HResult(pub u32);

impl HResult {
	pub const SUCCESS: HResult = HResult(0x0000_0000);

	pub const XONLINETASK_S_SUCCESS:       HResult = HResult(0x0015_00F0);
	pub const XONLINETASK_S_RESULTS_AVAIL: HResult = HResult(0x0015_00F1);
	pub const XONLINETASK_S_RUNNING_IDLE:  HResult = HResult(0x0015_00F2);

	pub fn is_successful(&self) -> bool {
		self.0 & 0x8000_0000 != 0
	}

	pub fn is_failure(&self) -> bool {
		!self.is_successful()
	}
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for HResult {
	fn put(&self, buf: &mut AnyBufMut) {
		buf.put_u32_le(self.0)
	}
}

impl Decode for HResult {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, val) = le_u32(input)?;
		Ok((input, HResult(val)))
	}
}
