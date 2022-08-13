use bytes::BufMut;

use nom::number::complete::le_u16;

use xbox_sys::codec::{BufPut, Decode, decode_array_u8};

use crate::net::{InAddr, Eui48};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Addr {
	pub addr: InAddr,
	pub addr_online: InAddr,
	pub port_online: u16,
	pub enet: Eui48,
	pub online: [u8;20],
}

impl Addr {
	pub const ENCODED_LEN: usize = 4 + 4 + 2 + 6 + 20;
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for Addr {
	fn put(&self, buf: &mut AnyBufMut) {
		self.addr.put(buf);
		self.addr_online.put(buf);
		buf.put_u16_le(self.port_online);
		self.enet.put(buf);
		buf.put_slice(&self.online);
	}
}

impl Decode for Addr {
	fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
		let (input, addr) = InAddr::decode(input)?;
		let (input, addr_online) = InAddr::decode(input)?;
		let (input, port_online) = le_u16(input)?;
		let (input, enet) = Eui48::decode(input)?;
		let (input, online) = decode_array_u8(input)?;

		Ok((input, Addr {
			addr,
			addr_online,
			port_online,
			enet,
			online,
		}))
	}
}