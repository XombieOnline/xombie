use bytes::BufMut;

use nom::number::streaming::le_u16;

use xbox_sys::codec::{BufPut, Decode};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LibraryVersion {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub qfe: u16,
}

impl LibraryVersion {
    pub fn from_raw(raw: &[u8]) -> Option<LibraryVersion> {
        let (remainder, library_version) = Self::decode(raw)
            .ok()?;

        if remainder.len() == 0 {
            Some(library_version)
        } else {
            None
        }
    }
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for LibraryVersion {
    fn put(&self, buf: &mut AnyBufMut) {
        buf.put_u16_le(self.major);
        buf.put_u16_le(self.minor);
        buf.put_u16_le(self.build);
        buf.put_u16_le(self.qfe);
    }
}

impl Decode for LibraryVersion {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, major) = le_u16(input)?;
        let (input, minor) = le_u16(input)?;
        let (input, build) = le_u16(input)?;
        let (input, qfe) = le_u16(input)?;

        Ok((input, LibraryVersion {
            major,
            minor,
            build,
            qfe,
        }))
    }
}