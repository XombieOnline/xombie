use bytes::BufMut;

use kerberos_asn1::Asn1Object;

use nom::number::streaming::{le_u16, le_u32, le_u8};

use std::convert::TryInto;

use xbox_sys::codec::Decode;

use crate::net::InAddr;
use crate::sg::SgAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tag(u16);

impl Tag {
    pub const DELETE:               Tag = Tag(0x5300);
    pub const PULSE:                Tag = Tag(0x5301);
    pub const XB_TO_SG_PULSE:       Tag = Tag(0x5302);
    pub const XB_TO_SG_QOS_INIT:    Tag = Tag(0x5307);
    pub const SG_TO_XB_QOS_RESP:    Tag = Tag(0x5308);
    pub const SG_TO_XB_PULSE:       Tag = Tag(0x5309);
    pub const KEY_EX_XB_TO_SG_INIT: Tag = Tag(0x5802);
    pub const KEY_EX_SG_TO_XB_RESP: Tag = Tag(0x5803);
    pub const DIFFIE_HELLMAN:       Tag = Tag(0x5880);
    pub const AP_REQ:               Tag = Tag(0x5882);
    pub const AP_REP:               Tag = Tag(0x5883);
    pub const PADDING:              Tag = Tag(0x5886);
}

#[derive(Debug)]
#[repr(C)]
pub struct Delete {
    pub reason: u32,
}

impl Delete {
    fn from_raw(tag: Tag, i: &[u8]) -> Result<Delete, FromRawError> {
        if i.len() != std::mem::size_of::<Self>() {
            return Err(FromRawError::IncorrectSize((tag, i.len())))
        }

        Self::decode(i)
            .map(|(_, pkt)| pkt)
            .map_err(|_| FromRawError::Parse("Delete".to_string()))
    }

    fn build(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.put_u32_le(self.reason);

        buf
    }
}

impl Decode for Delete {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, reason) = le_u32(input)?;

        Ok((input, Delete {
            reason,
        }))
    }
}

#[derive(Debug, PartialEq)]
pub struct XbToSgPulse<'a> {
    pub seq_ack: u32,
    pub events: &'a [u8],
}

impl<'a> XbToSgPulse<'a> {
    fn parse(i: &'a [u8]) -> nom::IResult<&[u8], XbToSgPulse<'a>> {
        let (i, seq_ack) = le_u32(i)?;

        Ok((&[], XbToSgPulse {
            seq_ack,
            events: i,
        }))
    }

    fn from_raw(tag: Tag, i: &'a[u8]) -> Result<XbToSgPulse<'a>, FromRawError> {
        if i.len() < std::mem::size_of::<u32>() {
            return Err(FromRawError::IncorrectSize((tag, i.len())))
        }

        Self::parse(i)
            .map(|(_, pkt)| pkt)
            .map_err(|_| FromRawError::Parse("XbToSgPulse".to_string()))
    }

    fn build(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.put_u32_le(self.seq_ack);
        for event in self.events {
            buf.push(*event);
        }

        buf
    }
}

#[derive(Debug, PartialEq)]
pub struct SgToXbPulse<'a> {
    pub seq_ack: u32,
    pub events: &'a [u8],
}

impl<'a> SgToXbPulse<'a> {
    fn parse(i: &'a [u8]) -> nom::IResult<&[u8], SgToXbPulse<'a>> {
        let (i, seq_ack) = le_u32(i)?;

        Ok((&[], SgToXbPulse {
            seq_ack,
            events: i,
        }))
    }

    fn from_raw(tag: Tag, i: &'a[u8]) -> Result<SgToXbPulse<'a>, FromRawError> {
        if i.len() < std::mem::size_of::<u32>() {
            return Err(FromRawError::IncorrectSize((tag, i.len())))
        }

        Self::parse(i)
            .map(|(_, pkt)| pkt)
            .map_err(|_| FromRawError::Parse("SgToXbPulse".to_string()))
    }

    fn build(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.put_u32_le(self.seq_ack);
        for event in self.events {
            buf.push(*event);
        }

        buf
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct XbToSgQosInit {
    pub nonce: [u8;8],
    pub qos_idx: u16,
    pub pkt_idx: u8,
    pub flags: u8,
}

fn parse_nonce(i: &[u8]) -> nom::IResult<&[u8], [u8;8]> {
    if i.len() < 8 {
        Err(nom::Err::Incomplete(nom::Needed::Unknown))
    } else {
        let rem = &i[8..];
        let nonce_slice = &i[..8];
        Ok((rem, nonce_slice.try_into().unwrap()))
    }
}

impl XbToSgQosInit {
    fn parse(i: &[u8]) -> nom::IResult<&[u8], XbToSgQosInit> {
        let (i, nonce) = parse_nonce(i)?;
        let (i, qos_idx) = le_u16(i)?;
        let (i, pkt_idx) = le_u8(i)?;
        let (i, flags) = le_u8(i)?;

        Ok((i, XbToSgQosInit {
            nonce,
            qos_idx,
            pkt_idx,
            flags,
        }))
    }

    fn from_raw(tag: Tag, i: &[u8]) -> Result<XbToSgQosInit, FromRawError> {
        if i.len() != std::mem::size_of::<Self>() {
            return Err(FromRawError::IncorrectSize((tag, i.len())))
        }

        Self::parse(i)
            .map(|(_, pkt)| pkt)
            .map_err(|_| FromRawError::Parse("XbToSgQosInit".to_string()))
    }

    fn build(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.append(&mut self.nonce.to_vec());
        buf.put_u16_le(self.qos_idx);
        buf.put_u8(self.pkt_idx);
        buf.put_u8(self.flags);

        buf
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct SgToXbQosResp {
    pub nonce: [u8;8],
    pub qos_idx: u16,
    pub pkt_idx: u8,
    pub flags: u8,
    pub us_rtt: u32,
    pub us_gap: u32,
}

impl SgToXbQosResp {
    fn parse(i: &[u8]) -> nom::IResult<&[u8], SgToXbQosResp> {
        let (i, nonce) = parse_nonce(i)?;
        let (i, qos_idx) = le_u16(i)?;
        let (i, pkt_idx) = le_u8(i)?;
        let (i, flags) = le_u8(i)?;
        let (i, us_rtt) = le_u32(i)?;
        let (i, us_gap) = le_u32(i)?;

        Ok((i, SgToXbQosResp {
            nonce,
            qos_idx,
            pkt_idx,
            flags,
            us_rtt,
            us_gap,
        }))
    }

    fn from_raw(tag: Tag, i: &[u8]) -> Result<SgToXbQosResp, FromRawError> {
        if i.len() != std::mem::size_of::<Self>() {
            return Err(FromRawError::IncorrectSize((tag, i.len())))
        }

        Self::parse(i)
            .map(|(_, pkt)| pkt)
            .map_err(|_| FromRawError::Parse("SgToXbQosResp".to_string()))
    }

    fn build(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.append(&mut self.nonce.to_vec());
        buf.put_u16_le(self.qos_idx);
        buf.put_u8(self.pkt_idx);
        buf.put_u8(self.flags);
        buf.put_u32_le(self.us_rtt);
        buf.put_u32_le(self.us_gap);

        buf
    }
}
#[derive(Debug)]
#[repr(C)]
pub struct KeyExXbToSgInit {
    pub version: u16,
    pub flags: u16,
    pub spi: u32,
    pub nonce: [u8;8],
    pub user_perm: u32,
}

impl KeyExXbToSgInit {
    fn parse(i: &[u8]) -> nom::IResult<&[u8], KeyExXbToSgInit> {
        let (i, version) = le_u16(i)?;
        let (i, flags) = le_u16(i)?;
        let (i, spi) =  le_u32(i)?;
        let (i, nonce) = parse_nonce(i)?;
        let (i, user_perm) = le_u32(i)?;

        Ok((i, KeyExXbToSgInit {
            version,
            flags,
            spi,
            nonce,
            user_perm,
        }))
    }

    fn from_raw(tag: Tag, i: &[u8]) -> Result<KeyExXbToSgInit, FromRawError> {
        if i.len() != std::mem::size_of::<Self>() {
            return Err(FromRawError::IncorrectSize((tag, i.len())))
        }

        Self::parse(i)
            .map(|(_, pkt)| pkt)
            .map_err(|_| FromRawError::Parse("KeyExXbToSgInit".to_string()))
    }

    fn build(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.put_u16_le(self.version);
        buf.put_u16_le(self.flags);
        buf.put_u32_le(self.spi);
        buf.append(&mut self.nonce.to_vec());
        buf.put_u32_le(self.user_perm);

        buf
    }
}

pub const KEY_EX_SG_TO_XB_RESP_FLAG_DES:  u16 = 0x0001;
pub const KEY_EX_SG_TO_XB_RESP_FLAG_3DES: u16 = 0x0002;

#[derive(Debug)]
#[repr(C)]
pub struct KeyExSgToXbResp {
    pub version: u16,
    pub flags: u16,
    pub spi_init: u32,
    pub spi_resp: u32,
    pub nonce_init: [u8;8],
    pub nonce_resp: [u8;8],
    pub sg_addr_init: SgAddr,
    pub ina_init: InAddr,
    pub port_init: u16,
    pub xb_to_sg_timeout_in_secs: u16,
    pub xb_to_sg_pulse_timeout_in_secs: u16,
    pub zero_pad: [u8;2],
}

impl KeyExSgToXbResp {
    fn build(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.put_u16_le(self.version);
        buf.put_u16_le(self.flags);
        buf.put_u32_le(self.spi_init);
        buf.put_u32_le(self.spi_resp);
        buf.append(&mut self.nonce_init.to_vec());
        buf.append(&mut self.nonce_resp.to_vec());
        buf.append(&mut self.sg_addr_init.build());
        buf.append(&mut self.ina_init.build());
        buf.put_u16(self.port_init);  // yes, this is big endian
        buf.put_u16_le(self.xb_to_sg_timeout_in_secs);
        buf.put_u16_le(self.xb_to_sg_pulse_timeout_in_secs);
        buf.append(&mut self.zero_pad.to_vec());

        buf
    }
}



#[derive(Debug)]
pub struct DiffieHellmanControlChunk<'a> {
    pub g_x: &'a [u8],
}

impl<'a> DiffieHellmanControlChunk<'a> {
    fn from_raw(tag: Tag, i: &'a [u8]) -> Result<DiffieHellmanControlChunk<'a>, FromRawError> {
        if i.len() != 96 {
            return Err(FromRawError::IncorrectSize((tag, i.len())));
        }

        Ok(DiffieHellmanControlChunk{
            g_x: i,
        })
    }

    fn build(&self) -> Vec<u8> {
        self.g_x.to_vec()
    }
}

#[derive(Debug)]
pub struct PaddingControlChunk<'a> {
    pub bytes: &'a [u8],
}

impl<'a> PaddingControlChunk<'a> {
    fn build(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

#[derive(Debug)]
pub enum FromRawError {
    IncorrectSize((Tag, usize)),
    Parse(String),
}

#[derive(Debug)]
pub enum ControlChunk<'a> {
    Delete(Delete),
    Pulse,
    XbToSgPulse(XbToSgPulse<'a>),
    SgToXbPulse(SgToXbPulse<'a>),
    XbToSgQosInit(XbToSgQosInit),
    SgToXbQosResp(SgToXbQosResp),
    KeyExXbToSgInit(KeyExXbToSgInit),
    KeyExSgToXbResp(KeyExSgToXbResp),
    DiffieHellman(DiffieHellmanControlChunk<'a>),
    ApReq(kerberos_asn1::ApReq),
    ApRep(kerberos_asn1::ApRep),
    Padding(PaddingControlChunk<'a>),
    Unknown(RawControlChunk<'a>),
}

impl<'a> ControlChunk<'a> {
    pub fn from_raw(raw: RawControlChunk<'a>) -> Result<ControlChunk<'a>, FromRawError> {
        Ok(match raw.tag {
            Tag::DELETE => ControlChunk::Delete(Delete::from_raw(
                raw.tag.clone(), raw.data)?),
            Tag::PULSE => ControlChunk::Pulse,
            Tag::XB_TO_SG_PULSE => ControlChunk::XbToSgPulse(XbToSgPulse::from_raw(
                raw.tag.clone(), raw.data)?),
            Tag::SG_TO_XB_PULSE => ControlChunk::SgToXbPulse(SgToXbPulse::from_raw(
                raw.tag.clone(), raw.data)?),
            Tag::XB_TO_SG_QOS_INIT => ControlChunk::XbToSgQosInit(XbToSgQosInit::from_raw(
                raw.tag.clone(), raw.data)?),
            Tag::SG_TO_XB_QOS_RESP => ControlChunk::SgToXbQosResp(SgToXbQosResp::from_raw(
                raw.tag.clone(), raw.data)?),
            Tag::KEY_EX_XB_TO_SG_INIT => ControlChunk::KeyExXbToSgInit(KeyExXbToSgInit::from_raw(
                raw.tag.clone(), raw.data)?),
            Tag::DIFFIE_HELLMAN => ControlChunk::DiffieHellman(DiffieHellmanControlChunk::from_raw(
                raw.tag.clone(), raw.data)?),
            Tag::AP_REQ => {
                let (rem, as_req) = kerberos_asn1::ApReq::parse(raw.data)
                    .map_err(|err| FromRawError::Parse(format!("ApReq parse error: {} <- {:02x?}", err, raw.data)))?;
                if !rem.is_empty() {
                    return Err(FromRawError::IncorrectSize((raw.tag.clone(), raw.data.len())));
                }
                ControlChunk::ApReq(as_req)
            }
            Tag::PADDING => ControlChunk::Padding(PaddingControlChunk{ bytes: raw.data }),
            _ => ControlChunk::Unknown(raw),
        })
    }

    pub fn tag(&self) -> Tag {
        use ControlChunk::*;

        match self {
            Delete(_)              => Tag::DELETE,
            Pulse                  => Tag::PULSE,
            XbToSgPulse(_)         => Tag::XB_TO_SG_PULSE,
            SgToXbPulse(_)         => Tag::SG_TO_XB_PULSE,
            XbToSgQosInit(_)       => Tag::XB_TO_SG_QOS_INIT,
            SgToXbQosResp(_)       => Tag::SG_TO_XB_QOS_RESP,
            KeyExXbToSgInit(_)     => Tag::KEY_EX_XB_TO_SG_INIT,
            KeyExSgToXbResp(_)     => Tag::KEY_EX_SG_TO_XB_RESP,
            DiffieHellman(_)       => Tag::DIFFIE_HELLMAN,
            ApReq(_)               => Tag::AP_REQ,
            ApRep(_)               => Tag::AP_REP,
            Padding(_)             => Tag::PADDING,
            Unknown(raw) => raw.tag.clone(),
        }
    }

    fn body_vec(&self) -> Vec<u8> {
        use ControlChunk::*;

        match self {
            Delete(chunk) => chunk.build(),
            Pulse => vec![],
            XbToSgPulse(chunk) => chunk.build(),
            SgToXbPulse(chunk) => chunk.build(),
            XbToSgQosInit(chunk) => chunk.build(),
            SgToXbQosResp(chunk) => chunk.build(),
            KeyExXbToSgInit(chunk) => chunk.build(),
            KeyExSgToXbResp(chunk) => chunk.build(),
            DiffieHellman(chunk) => chunk.build(),
            ApReq(ap_req) => ap_req.build(),
            ApRep(ap_rep) => ap_rep.build(),
            Padding(chunk) => chunk.build(),
            Unknown(raw) => raw.build_body(),
        }
    }

    pub fn build(&self) -> Option<Vec<u8>> {
        let mut ret = vec![];

        ret.append(&mut self.tag().0.to_le_bytes().to_vec());
        ret.append(&mut 0u16.to_le_bytes().to_vec());
        let mut body = self.body_vec();
        let len = body.len() + 4; // 4 for header above, two u16s
        ret.append(&mut body);

        // write total length into header
        if len > (u16::MAX as usize) {
            return None;
        }

        ret[2] = (len >> 0) as u8;
        ret[3] = (len >> 8) as u8;

        Some(ret)
    }
}

#[derive(Debug, PartialEq)]
pub struct RawControlChunk<'a> {
    pub tag: Tag,
    pub len: u16,
    pub data: &'a [u8],
}

impl<'a> RawControlChunk<'a> {
    pub fn parse(i: &'a [u8]) -> nom::IResult<&'a [u8], RawControlChunk<'a>> {
        let (i, tag) = le_u16(i)?;
        let (i, len) = le_u16(i)?;

        let data_len = len as usize - 4;

        if i.len() < data_len {
            return Err(nom::Err::Incomplete(nom::Needed::Unknown))
        }

        let data = &i[..data_len];
        let rem = &i[data_len..];

        Ok((rem, RawControlChunk {
            tag: Tag(tag),
            len,
            data,
        }))
    }

    fn build_body(&self) -> Vec<u8> {
        self.data.to_vec()
    }
}

#[derive(Debug, PartialEq)]
pub struct ControlPacket<'a> {
    pub data: &'a [u8],
}

impl<'a> ControlPacket<'a> {
    pub fn parse(i: &'a [u8]) -> nom::IResult<&'a [u8], ControlPacket<'a>> {
        Ok((&i[0..0],
            ControlPacket {
                data: i,
            }
        ))
    }

    pub fn raw_control_chunk_iter(&'a self) -> RawControlChunkIter<'a> {
        RawControlChunkIter {
            remaining_data: self.data,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct RawControlChunkIter<'a> {
    remaining_data: &'a [u8],
}

impl<'a> Iterator for RawControlChunkIter<'a> {
    type Item = RawControlChunk<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (rem, pkt) = RawControlChunk::parse(self.remaining_data).ok()?;

        self.remaining_data = rem;

        Some(pkt)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::crypto::primitives::DIFFIE_HELLMAN_MOD_LENGTH;

    use xbox_sys::account::Xuid;

    use super::*;

    #[test]
    fn parse_simple_control_packet() {
        let pkt_bytes = hex!["
            AD DE 08 00 EF BE AD DE"];

        let (remainder, ctrl_packet) = ControlPacket::parse(&pkt_bytes).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(ctrl_packet, ControlPacket {
            data: &hex!["AD DE 08 00 EF BE AD DE"],
        });
    }

    #[test]
    fn parse_raw_control_chunk() {
        let chunk_bytes = hex!["AD DE 08 00 EF BE AD DE"];

        let (remainder, raw_ctrl_chunk) = RawControlChunk::parse(&chunk_bytes).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(raw_ctrl_chunk, RawControlChunk {
            tag: Tag(0xDEAD),
            len: 8,
            data: &hex!["EF BE AD DE"],
        });
    }

    #[test]
    fn parse_complete_packet() {
        let pkt_bytes = hex!["
            02 58
            18 00
            00 00 00 00 00 a3 59 00 25 32 55 23 1a 64 4f e4
            00 00 00 00

            80 58
            64 00
            28 08 19 2b 0f 01 fc 37 1e 27 31 5d 4f c2 c4 f0
            81 32 55 b5 7d 4a af 2a 76 91 59 63 54 e8 5a ce
            64 ee 55 f4 84 a9 a2 53 c3 02 17 4e 56 56 d5 1e
            3e d5 d8 7c 57 88 62 b8 53 31 53 f5 ad 1e c5 c1
            fd 0a b2 4f fa 1c 46 df 12 91 9d 5a 43 32 9e 9d
            e2 42 23 af 7e 98 16 12 3d f3 b5 f9 03 99 89 c6

            82 58
            b7 01
            6e 82 01 af 30 82 01 ab a0 03 02 01 05 a1 03 02
            01 0e a2 07 03 05 00 20 00 00 00 a3 81 eb 61 81
            e8 30 81 e5 a0 03 02 01 05 a1 0a 1b 08 58 42 4f
            58 2e 43 4f 4d a2 13 30 11 a0 03 02 01 02 a1 0a
            30 08 1b 02 73 67 1b 02 53 32 a3 81 bc 30 81 b9
            a0 03 02 01 17 a2 81 b1 04 81 ae 9c 73 e1 d4 2b
            55 4a e3 dc 33 50 ea 07 3b 53 fe 13 2a f1 cb 44
            36 52 3e 7c 4b bc 5c d9 d7 e5 f7 ac 1c b5 6e 74
            ba 3c ab df 7e 43 81 0f 12 47 cf ce ea 52 36 0b
            c1 d0 ab b7 75 cc 90 53 c1 7a 9a 34 22 bc d2 c8
            72 9b cd 5d 44 e5 aa 15 ca 37 78 95 c2 f9 75 da
            e2 ed 64 34 15 0f 76 7a 68 af 9a 39 cb 1f 3a 32
            d9 7e 4f 02 30 f2 26 eb ae 55 31 38 c3 30 3e c8
            65 b4 a4 07 38 37 f0 92 91 20 e9 b8 2b a9 dc d6
            a5 ba 99 c9 d3 b1 31 34 97 69 3c 75 4d 8c 68 e4
            a0 b5 a7 eb 9b 88 49 eb 05 fd aa 5b fc 8e 26 f3
            c5 3b 5d c6 13 6b f1 93 cb a4 81 a7 30 81 a4 a0
            03 02 01 17 a2 81 9c 04 81 99 c4 18 8b d2 51 81
            66 b6 95 54 aa 1c 4b 75 d0 7b 2e d9 19 c0 8b 38
            7e fa ba 52 c9 ec 40 7f 57 0b be d5 7c 39 2d 99
            b3 e7 a0 07 17 fc e0 d2 25 71 04 e8 30 51 2f 71
            ca c8 f1 54 7c 1d 70 06 65 bc da 2a aa 29 9b 8e
            a2 d9 37 b2 09 cc 3b 83 06 3c 59 85 72 a2 ed 21
            7f f0 e7 25 a3 97 54 09 f1 75 57 54 68 47 8b 04
            c9 cf e9 f9 d9 5e bc 5e df 25 fe 59 a9 5e b2 fd
            30 44 57 0c 58 a3 64 94 45 e3 ab f0 4e 16 cc 62
            3e d2 8c a2 53 97 bf e8 3e c5 a3 6f 6d 76 dc a5
            a2 ac af

            86 58
            01 03
            3f 42 3f 9e a3 24 c6 bc 55 37 d3 01 a4 17 0d a4 57 14 2d f5 56 22 79 52 8b b6 7e 4f 95 fd cb 20
            bb 16 a9 2c f8 4f 96 cc 2a b0 bb 9b f0 45 1e 1a 3b f5 88 ba fe 7c 6d cf d9 e2 fd eb 81 eb 5f 75
            ce 50 7f 0a da 13 ab 4c fc c9 3d ef d4 1f 60 24 91 47 85 12 c5 5c 23 9b 12 9d 14 ac 26 5e 27 3d
            c7 52 c8 d1 b6 f6 ff e3 d1 13 cc 6c b1 43 35 38 4b 65 53 cb 97 54 16 2e e9 26 87 10 5f bd ad af
            6c da 5e ae 8e a4 9e 5b 29 4a e7 73 e3 6f 4f ed ab 10 47 0e 2f 54 47 58 f2 a3 dc b3 b1 6a da 9d
            07 71 20 b6 7d 6c 81 12 bf 46 81 47 c2 57 ed 05 b8 85 09 d0 09 e4 f2 aa 13 00 5f a0 7f 84 a0 8e
            4a 2a d7 16 39 6f da 45 c0 59 49 2f d2 4e 8e 43 54 08 0d 36 92 c5 09 fa 46 ab 85 b2 28 e4 22 6c
            03 cf 0c 1d ea 3f 71 76 fe 25 df 06 95 eb 9c a9 36 93 e7 8e 2c 6d 9b 58 1b 29 48 d1 ee af fe 4f
            5d 98 3a 44 b5 4a d0 15 2c b3 2d ea 30 61 6e f9 81 c2 a5 e3 df d9 83 ec 6c 73 a9 f5 47 92 ba 0b
            69 b6 38 f4 1e 64 af e5 71 83 03 f5 15 32 dc 5e 97 8c 63 b3 94 9a b0 77 f2 49 69 13 ae c8 55 65
            03 dd b4 c2 d2 47 3b 3c a8 13 f0 f9 fb dc 3a 61 bc 15 b9 75 3d c8 bc 78 1d ce b4 9d 49 a0 5f d0
            46 72 3f f1 01 69 d5 34 99 88 e0 dd 81 e9 23 b4 96 8a 5e f7 20 a9 03 ab 3c 9c 91 9e aa ef ad 5e
            6b 7b 25 bc 40 56 33 3f 27 bc 4b 3c 61 b2 9e 03 4d 58 5b ee e3 bd cb fc dd 3f 85 80 af 91 b8 a1
            08 52 d2 3c b4 ba e8 8d 56 76 e1 0a ea 8f df a6 69 5e b1 c5 ed 82 8e 85 e0 ad 70 16 5d d0 93 92
            9f 6c 42 ca 1a fd 98 29 fa d4 4b 46 91 84 60 c6 95 13 9b 21 5a 44 5f 2c 25 19 b3 4f 78 b4 e6 16
            25 03 17 6f df 02 a2 52 e8 f2 3b 9b 39 9f d6 34 26 56 74 02 44 09 e3 36 1f 33 bc 8f 27 78 ba 6b
            00 60 08 dd 84 fd 38 45 f6 ed f7 24 bd 7e e8 47 1e ff 5c 5d 3c 2a df 09 ab bc 62 ea ca 9c ab 6a
            59 ff b5 77 4b 00 ea f5 f9 1f a6 8d 6f b4 7b 13 2e ea 46 98 08 8b d2 27 80 34 3e bc 2e c3 15 06
            43 75 90 12 97 0b 2f 69 df a5 72 cf f2 37 fe 42 1e 5d 64 f8 54 a7 8a 3e 79 6f 4f 08 5b 40 58 64
            87 b2 b4 4a 91 01 61 87 c4 c9 7a 22 b2 80 1f 7a 29 86 af 4e 7d f1 a9 a4 e2 d3 b0 35 26 a7 46 ef
            ef 5d af fe fd 5d ee 84 e4 b9 87 50 7d a1 b2 0e 91 97 aa 90 a4 be 48 77 8d df df 48 0b 4b b7 a7
            d7 c0 51 c8 4d fb 14 eb 76 d9 45 a7 c4 f4 59 89 f7 87 a0 3c c9 b3 70 85 08 84 b3 db cb 58 e3 a1
            b3 a4 f0 ee b3 cb ce 05 7a 52 09 03 85 71 dc 2b 37 3d 6b 92 2f e5 5b 9d 3d fd 61 8f 8a b7 04 ac
            e7 1d 6c d7 29 0d 4b 03 fe 9c e7 00 3b 87 dc 5d 30 46 21 0a ce 66 b9 8f 0f d3 76 d6 0a"];

        let (remainder, ctrl_packet) = ControlPacket::parse(&pkt_bytes).unwrap();

        assert!(remainder.is_empty());

        assert_eq!(ctrl_packet.raw_control_chunk_iter().collect::<Vec<RawControlChunk<'_>>>(), vec![
            RawControlChunk {
                tag: Tag::KEY_EX_XB_TO_SG_INIT,
                len: 0x18,
                data: &hex!["
                    00 00 00 00 00 a3 59 00 25 32 55 23 1a 64 4f e4
                    00 00 00 00
                "],
            },
            RawControlChunk {
                tag: Tag::DIFFIE_HELLMAN,
                len: 0x64,
                data: &hex!["
                    28 08 19 2b 0f 01 fc 37 1e 27 31 5d 4f c2 c4 f0
                    81 32 55 b5 7d 4a af 2a 76 91 59 63 54 e8 5a ce
                    64 ee 55 f4 84 a9 a2 53 c3 02 17 4e 56 56 d5 1e
                    3e d5 d8 7c 57 88 62 b8 53 31 53 f5 ad 1e c5 c1
                    fd 0a b2 4f fa 1c 46 df 12 91 9d 5a 43 32 9e 9d
                    e2 42 23 af 7e 98 16 12 3d f3 b5 f9 03 99 89 c6
                "],
            },
            RawControlChunk {
                tag: Tag::AP_REQ,
                len: 0x1b7,
                data: &hex!["
                    6e 82 01 af 30 82 01 ab a0 03 02 01 05 a1 03 02
                    01 0e a2 07 03 05 00 20 00 00 00 a3 81 eb 61 81
                    e8 30 81 e5 a0 03 02 01 05 a1 0a 1b 08 58 42 4f
                    58 2e 43 4f 4d a2 13 30 11 a0 03 02 01 02 a1 0a
                    30 08 1b 02 73 67 1b 02 53 32 a3 81 bc 30 81 b9
                    a0 03 02 01 17 a2 81 b1 04 81 ae 9c 73 e1 d4 2b
                    55 4a e3 dc 33 50 ea 07 3b 53 fe 13 2a f1 cb 44
                    36 52 3e 7c 4b bc 5c d9 d7 e5 f7 ac 1c b5 6e 74
                    ba 3c ab df 7e 43 81 0f 12 47 cf ce ea 52 36 0b
                    c1 d0 ab b7 75 cc 90 53 c1 7a 9a 34 22 bc d2 c8
                    72 9b cd 5d 44 e5 aa 15 ca 37 78 95 c2 f9 75 da
                    e2 ed 64 34 15 0f 76 7a 68 af 9a 39 cb 1f 3a 32
                    d9 7e 4f 02 30 f2 26 eb ae 55 31 38 c3 30 3e c8
                    65 b4 a4 07 38 37 f0 92 91 20 e9 b8 2b a9 dc d6
                    a5 ba 99 c9 d3 b1 31 34 97 69 3c 75 4d 8c 68 e4
                    a0 b5 a7 eb 9b 88 49 eb 05 fd aa 5b fc 8e 26 f3
                    c5 3b 5d c6 13 6b f1 93 cb a4 81 a7 30 81 a4 a0
                    03 02 01 17 a2 81 9c 04 81 99 c4 18 8b d2 51 81
                    66 b6 95 54 aa 1c 4b 75 d0 7b 2e d9 19 c0 8b 38
                    7e fa ba 52 c9 ec 40 7f 57 0b be d5 7c 39 2d 99
                    b3 e7 a0 07 17 fc e0 d2 25 71 04 e8 30 51 2f 71
                    ca c8 f1 54 7c 1d 70 06 65 bc da 2a aa 29 9b 8e
                    a2 d9 37 b2 09 cc 3b 83 06 3c 59 85 72 a2 ed 21
                    7f f0 e7 25 a3 97 54 09 f1 75 57 54 68 47 8b 04
                    c9 cf e9 f9 d9 5e bc 5e df 25 fe 59 a9 5e b2 fd
                    30 44 57 0c 58 a3 64 94 45 e3 ab f0 4e 16 cc 62
                    3e d2 8c a2 53 97 bf e8 3e c5 a3 6f 6d 76 dc a5
                    a2 ac af
                "],
            },
            RawControlChunk {
                tag: Tag::PADDING,
                len: 0x301,
                data: &hex!["
                    3f 42 3f 9e a3 24 c6 bc 55 37 d3 01 a4 17 0d a4 57 14 2d f5 56 22 79 52 8b b6 7e 4f 95 fd cb 20
                    bb 16 a9 2c f8 4f 96 cc 2a b0 bb 9b f0 45 1e 1a 3b f5 88 ba fe 7c 6d cf d9 e2 fd eb 81 eb 5f 75
                    ce 50 7f 0a da 13 ab 4c fc c9 3d ef d4 1f 60 24 91 47 85 12 c5 5c 23 9b 12 9d 14 ac 26 5e 27 3d
                    c7 52 c8 d1 b6 f6 ff e3 d1 13 cc 6c b1 43 35 38 4b 65 53 cb 97 54 16 2e e9 26 87 10 5f bd ad af
                    6c da 5e ae 8e a4 9e 5b 29 4a e7 73 e3 6f 4f ed ab 10 47 0e 2f 54 47 58 f2 a3 dc b3 b1 6a da 9d
                    07 71 20 b6 7d 6c 81 12 bf 46 81 47 c2 57 ed 05 b8 85 09 d0 09 e4 f2 aa 13 00 5f a0 7f 84 a0 8e
                    4a 2a d7 16 39 6f da 45 c0 59 49 2f d2 4e 8e 43 54 08 0d 36 92 c5 09 fa 46 ab 85 b2 28 e4 22 6c
                    03 cf 0c 1d ea 3f 71 76 fe 25 df 06 95 eb 9c a9 36 93 e7 8e 2c 6d 9b 58 1b 29 48 d1 ee af fe 4f
                    5d 98 3a 44 b5 4a d0 15 2c b3 2d ea 30 61 6e f9 81 c2 a5 e3 df d9 83 ec 6c 73 a9 f5 47 92 ba 0b
                    69 b6 38 f4 1e 64 af e5 71 83 03 f5 15 32 dc 5e 97 8c 63 b3 94 9a b0 77 f2 49 69 13 ae c8 55 65
                    03 dd b4 c2 d2 47 3b 3c a8 13 f0 f9 fb dc 3a 61 bc 15 b9 75 3d c8 bc 78 1d ce b4 9d 49 a0 5f d0
                    46 72 3f f1 01 69 d5 34 99 88 e0 dd 81 e9 23 b4 96 8a 5e f7 20 a9 03 ab 3c 9c 91 9e aa ef ad 5e
                    6b 7b 25 bc 40 56 33 3f 27 bc 4b 3c 61 b2 9e 03 4d 58 5b ee e3 bd cb fc dd 3f 85 80 af 91 b8 a1
                    08 52 d2 3c b4 ba e8 8d 56 76 e1 0a ea 8f df a6 69 5e b1 c5 ed 82 8e 85 e0 ad 70 16 5d d0 93 92
                    9f 6c 42 ca 1a fd 98 29 fa d4 4b 46 91 84 60 c6 95 13 9b 21 5a 44 5f 2c 25 19 b3 4f 78 b4 e6 16
                    25 03 17 6f df 02 a2 52 e8 f2 3b 9b 39 9f d6 34 26 56 74 02 44 09 e3 36 1f 33 bc 8f 27 78 ba 6b
                    00 60 08 dd 84 fd 38 45 f6 ed f7 24 bd 7e e8 47 1e ff 5c 5d 3c 2a df 09 ab bc 62 ea ca 9c ab 6a
                    59 ff b5 77 4b 00 ea f5 f9 1f a6 8d 6f b4 7b 13 2e ea 46 98 08 8b d2 27 80 34 3e bc 2e c3 15 06
                    43 75 90 12 97 0b 2f 69 df a5 72 cf f2 37 fe 42 1e 5d 64 f8 54 a7 8a 3e 79 6f 4f 08 5b 40 58 64
                    87 b2 b4 4a 91 01 61 87 c4 c9 7a 22 b2 80 1f 7a 29 86 af 4e 7d f1 a9 a4 e2 d3 b0 35 26 a7 46 ef
                    ef 5d af fe fd 5d ee 84 e4 b9 87 50 7d a1 b2 0e 91 97 aa 90 a4 be 48 77 8d df df 48 0b 4b b7 a7
                    d7 c0 51 c8 4d fb 14 eb 76 d9 45 a7 c4 f4 59 89 f7 87 a0 3c c9 b3 70 85 08 84 b3 db cb 58 e3 a1
                    b3 a4 f0 ee b3 cb ce 05 7a 52 09 03 85 71 dc 2b 37 3d 6b 92 2f e5 5b 9d 3d fd 61 8f 8a b7 04 ac
                    e7 1d 6c d7 29 0d 4b 03 fe 9c e7 00 3b 87 dc 5d 30 46 21 0a ce 66 b9 8f 0f d3 76 d6 0a
                "],
            },
        ]);
    }

    #[test]
    fn key_ex_sg_to_xb_chunk_build() {
        let chunk = ControlChunk::KeyExSgToXbResp(KeyExSgToXbResp {
            version: 0xFFFF,
            flags: 0,
            spi_init: 0,
            spi_resp: 0,
            nonce_init: [0u8;8],
            nonce_resp: [0u8;8],
            sg_addr_init: SgAddr {
                ina_sg: InAddr([0xFFu8;4]),
                spi_sg: 0,
                xbox_id: Xuid::INVALID,
                _rsvd_10: [0u8;4],
            },
            ina_init: InAddr([0xFFu8;4]),
            port_init: 0,
            xb_to_sg_pulse_timeout_in_secs: 60,
            xb_to_sg_timeout_in_secs: 60,
            zero_pad: [0u8;2],
        });

        let bytes = chunk.build().unwrap();

        println!("{:02x?}", bytes);

        assert_eq!(chunk.build().unwrap().len(), 0x40);
    }

    #[test]
    fn dh_build() {
        let chunk = ControlChunk::DiffieHellman(DiffieHellmanControlChunk {
            g_x: &[0xFFu8;DIFFIE_HELLMAN_MOD_LENGTH],
        });

        assert_eq!(chunk.build().unwrap().len(), 100);
    }

    #[test]
    fn parse_xb_to_sg_pulse() {
        let i = &hex!["
            01 02 03 04
        "];

        let pulse = XbToSgPulse::from_raw(
            Tag::XB_TO_SG_PULSE,
            i).unwrap();

        assert_eq!(pulse, XbToSgPulse {
            seq_ack: 0x04030201,
            events: &[],
        })
    }
}