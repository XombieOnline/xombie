use bytes::BufMut;
use nom::number::complete::{be_u16, be_u32};

use std::mem::size_of;

use super::packet::PortLen;

pub const FOOTER_LEN: usize = 12;

pub const BYTE_0_LEN: usize = FOOTER_LEN;
pub const BYTE_1_LEN: usize = FOOTER_LEN + 2;
pub const BYTE_2_LEN: usize = FOOTER_LEN + 4;

pub const BASE_COMPRESSED_PORT: u16 = 1000;

pub const FIN: u16 = 0b_0000_0001;
pub const SYN: u16 = 0b_0000_0010;
pub const RST: u16 = 0b_0000_0100;
pub const PSH: u16 = 0b_0000_1000;
pub const ACK: u16 = 0b_0001_0000;

pub const FLAGS_MASK: u16 = 0x0FFF;

pub const RFC793_TCP_HEADER_LEN_IN_WORDS: usize = 5;

pub const OPTION_KIND_MSS: u8 = 2;

#[derive(Debug)]
pub struct TcpHeader {
    pub src: u16,
    pub dst: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub flags_and_header_size: u16,
    pub window: u16,
}

impl TcpHeader {
    pub fn parse_two_byte_port(i: &[u8]) -> nom::IResult<&[u8], TcpHeader>{
        let (i, src) = be_u16(i)?;
        let (i, dst) = be_u16(i)?;
        let (i, seq_num) = be_u32(i)?;
        let (i, ack_num) = be_u32(i)?;
        let (i, flags_and_header_size) = be_u16(i)?;
        let (i, window) = be_u16(i)?;

        Ok((i, TcpHeader {
            src,
            dst,
            seq_num,
            ack_num,
            flags_and_header_size,
            window,
        }))
    }

    pub fn build(&self) -> Vec<u8> {
        let mut buf = vec![];

        use PortLen::*;
        match self.port_len() {
            ZeroByte => {},
            SingleByte => {
                buf.put_u8((self.src - BASE_COMPRESSED_PORT) as u8);
                buf.put_u8((self.dst - BASE_COMPRESSED_PORT) as u8);
            }
            DoubleByte => {
                buf.put_u16(self.src);
                buf.put_u16(self.dst);
            }
        }

        buf.put_u32(self.seq_num);
        buf.put_u32(self.ack_num);
        buf.put_u16(self.flags_and_header_size);
        buf.put_u16(self.window);

        buf
    }

    pub fn flags(&self) -> u16 {
        self.flags_and_header_size & FLAGS_MASK
    }

    pub fn options_length(&self) -> usize {
        let total_header_length = (self.flags_and_header_size >> 12) as usize;
        if total_header_length <= RFC793_TCP_HEADER_LEN_IN_WORDS {
            return 0;
        } else {
            (total_header_length - RFC793_TCP_HEADER_LEN_IN_WORDS) * size_of::<u32>()
        }
    }

    pub fn port_len(&self) -> PortLen {
        PortLen::from_ports(self.src, self.dst)
    }

    pub fn set_options_length(&mut self, new_length: usize) {
        if new_length % size_of::<u32>() != 0 {
            panic!("options length is not a multiple of 4 {}", new_length);
        }

        let new_length = new_length / size_of::<u32>();
        let header_len = new_length + RFC793_TCP_HEADER_LEN_IN_WORDS;
        if header_len > 0xF {
            panic!("options length is larger than can be stored in packet");
        }

        self.flags_and_header_size &= FLAGS_MASK;
        self.flags_and_header_size |= (header_len as u16) << 12;
    }

    pub fn set_syn(&mut self) {
        self.flags_and_header_size |= SYN
    }

    pub fn set_ack(&mut self) {
        self.flags_and_header_size |= ACK
    }
}

#[derive(Debug)]
pub struct TcpOption<'a> {
    pub kind: u8,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub struct TcpOptionsIter<'a> {
    data: &'a [u8],
}

impl<'a> TcpOptionsIter<'a> {
    pub fn new(header: &TcpHeader, data: &'a [u8]) -> Self {
        TcpOptionsIter {
            data: &data[..header.options_length()]
        }
    }
}

impl<'a> Iterator for TcpOptionsIter<'a> {
    type Item = TcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < 2 {
            return None;
        }

        let kind = self.data[0];
        let len = self.data[1] as usize;
        if len > self.data.len() {
            return None;
        }

        if len < 2 {
            return None;
        }

        let option = TcpOption {
            kind,
            data: &self.data[2..len],
        };

        self.data = &self.data[len..];

        Some(option)
    }
}