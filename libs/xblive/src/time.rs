use bytes::BufMut;

use nom::number::complete::le_u64;

use xbox_sys::codec::{BufPut, Decode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TimeStamp(pub u64);

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for TimeStamp {
	fn put(&self, buf: &mut AnyBufMut) {
		buf.put_u64_le(self.0)
	}
}

impl Decode for TimeStamp {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, val) = le_u64(input)?;
		Ok((input, TimeStamp(val)))
	}
}
