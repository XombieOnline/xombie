use log::error;

use std::mem::size_of;

use xbox_sys::crypto::SymmetricKey;

use crate::arith::roundup;
use crate::crypto::derivation::TripleDesOneWayKeySet;
use crate::crypto::primitives::{sha1_hmac, tdes_cbc_decrypt_in_place, tdes_cbc_encrypt_in_place};
use crate::sg::SecurityParametersIndex;
use crate::sg::control::{ControlChunk, ControlPacket};
use crate::sg::seq::SeqNum;
use crate::sg::tcp::{TcpHeader, self};

#[derive(Debug, PartialEq)]
pub enum PortLen {
    ZeroByte,
    SingleByte,
    DoubleByte,
}

impl PortLen {
    pub fn from_ports(src: u16, dst: u16) -> PortLen {
        match (src, dst) {
            (1000, 1000) => PortLen::ZeroByte,
            (1000..=1255, 1000..=1255) => PortLen::SingleByte,
            _ => PortLen::DoubleByte,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Opcode {
    Control,
    Tcp0BytePort,
    Tcp1BytePort,
    Tcp2BytePort,
}

impl Opcode {
    pub fn protocol_footer_len(&self) -> usize {
        use Opcode::*;
        match self {
            Control => 0,
            Tcp0BytePort => tcp::BYTE_0_LEN,
            Tcp1BytePort => tcp::BYTE_1_LEN,
            Tcp2BytePort => tcp::BYTE_2_LEN,
        }
    }

    pub fn byte(&self) -> u8 {
        use Opcode::*;
        match self {
            Control => 0,
            Tcp0BytePort => 1,
            Tcp1BytePort => 2,
            Tcp2BytePort => 3,
        }
    }
}

#[derive(Debug)]
pub enum PacketCategorizaton {
    Invalid,
    ControlInit,
    Connection,
}

#[derive(Debug)]
#[repr(C)]
pub struct Header {
    pub prefix: u8,
    pub spi_bytes: [u8;3],
}

impl Header {
    pub fn new(opcode: Opcode, spi: SecurityParametersIndex, payload_len: usize) -> Self {
        let encrypted_len = roundup(payload_len, ENCRYPTION_BLOCK_SIZE);
        let encrypted_padding_len = encrypted_len - payload_len;

        let high_prefix = (encrypted_padding_len << 5) as u8;

        Header {
            prefix: high_prefix | opcode.byte(),
            spi_bytes: spi.0,
        }
    }

    pub fn from_buffer(buf: &[u8]) -> Option<Header> {
        if buf.len() >= size_of::<Self>() {
            Some(Header {
                prefix: buf[0],
                spi_bytes: [buf[1], buf[2], buf[3]],
            })
        } else {
            None
        }
    }

    pub fn opcode(&self) -> Option<Opcode> {
        use Opcode::*;
        Some(match self.prefix & 0b_1111 {
            0 => Control,
            1 => Tcp0BytePort,
            2 => Tcp1BytePort,
            3 => Tcp2BytePort,
            _ => return None,
        })
    }

    pub fn encrypted_padding_len(&self) -> usize {
        (self.prefix >> 5) as usize
    }

    pub fn spi(&self) -> SecurityParametersIndex {
        SecurityParametersIndex(self.spi_bytes)
    }

    pub fn categorize_packet(&self) -> PacketCategorizaton {
        use PacketCategorizaton::*;

        match (self.prefix, self.spi()) {
            (0, SecurityParametersIndex::EMPTY) => ControlInit,
            (_, SecurityParametersIndex::EMPTY) => Invalid,
            _                                   => Connection,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        vec![self.prefix, self.spi_bytes[0], self.spi_bytes[1], self.spi_bytes[2]]
    }
}

#[derive(Debug)]
pub enum PacketKind<'a> {
    Control(Vec<ControlChunk<'a>>),
}

#[derive(Debug)]
pub enum PacketParseError {
    TooSmall,
    UnknownOpcode(u8),
    Todo(&'static str),
    AuthError,
    DecryptError,
}

#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub data: Vec<u8>,

    pub lengths: PacketLengths,
    pub seq_num: SeqNum,
}

pub const ENCRYPTION_BLOCK_SIZE: usize = 8;

pub const HEADER_START: usize = 0;
pub const HEADER_END: usize = size_of::<Header>();
pub const PAYLOAD_START: usize = HEADER_END;
pub const SEQ_LEN: usize = 2;
pub const HIDDEN_SEQ_NUM_LEN: usize = 2;
pub const DIGEST_LEN: usize = 10;

pub const MIN_PACKET_SIZE: usize = size_of::<Header>() + SEQ_LEN + DIGEST_LEN;

impl Packet {
    pub fn decrypt_from(buf: &[u8], last_seq: SeqNum, keys: &TripleDesOneWayKeySet) -> Result<Packet, PacketParseError> {
        use PacketParseError::*;

        if buf.len() < MIN_PACKET_SIZE {
            return Err(TooSmall);
        }

        let header = Header::from_buffer(buf)
            .ok_or(TooSmall)?;

        let opcode = header.opcode()
            .ok_or(UnknownOpcode(header.prefix))?;

        let lengths = PacketLengths::new(buf.len(), &header, opcode);

        let seq_num = authenticate_packet(buf, &lengths, last_seq, keys.sha)
            .ok_or(AuthError)
            .map_err(|err| {
                eprintln!("authenticate error: buf:{:02x?} legnths:{:?} last_seq:{:?} keys:{:02x?}", buf, lengths, last_seq, keys);
                err
            })?;

        let seq_iv = seq_num.permute_iv(keys.iv);

        let enc_payload_len = buf.len() - MIN_PACKET_SIZE - lengths.unencrypted_protocol_footer_len;

        let mut data = Vec::from(&buf[PAYLOAD_START..lengths.footer_end]);

        tdes_cbc_decrypt_in_place(&keys.des, seq_iv, &mut data[..enc_payload_len])
            .map_err(|_| DecryptError)?;

        Ok(Packet {
            header,
            data,

            lengths,
            seq_num,
        })
    }

    pub fn payload<'a>(&'a self) -> &'a [u8] {
        &self.data[..self.lengths.payload_len]
    }

    pub fn protocol_footer<'a>(&'a self) -> &'a [u8] {
        let footer_base = self.data.len() - self.lengths.protocol_footer_len - SEQ_LEN;
        let footer_end = footer_base + self.lengths.protocol_footer_len;

        &self.data[footer_base..footer_end]
    }
}

#[derive(Debug, PartialEq)]
pub struct PacketLengths {
    pub protocol_footer_len: usize,
    pub unencrypted_protocol_footer_len: usize,
    pub enc_segment_len: usize,
    pub enc_segment_end: usize,
    pub payload_len: usize,
    pub footer_start: usize,
    pub footer_len: usize,
    pub footer_end: usize,
    pub digest_start: usize,
    pub digest_end: usize,
    pub num_digest_padding_bytes: usize,
}

impl PacketLengths {
    fn new(packet_len: usize, header: &Header, opcode: Opcode) -> Self {
        let protocol_footer_len = opcode.protocol_footer_len();

        let unencrypted_protocol_footer_len = if protocol_footer_len >= header.encrypted_padding_len() {
            protocol_footer_len - header.encrypted_padding_len()
        } else {
            0
        };

        let enc_segment_len = packet_len - (MIN_PACKET_SIZE + unencrypted_protocol_footer_len);
        let enc_segment_end = PAYLOAD_START + enc_segment_len;

        let payload_len = enc_segment_len - header.encrypted_padding_len();

        let footer_start = enc_segment_end;
        let footer_len = unencrypted_protocol_footer_len + SEQ_LEN;
        let footer_end = footer_start + footer_len;

        let digest_start = footer_end;
        let digest_end = digest_start + DIGEST_LEN;

        let num_digest_padding_bytes = (4 - ((footer_len + HIDDEN_SEQ_NUM_LEN) % 4)) % 4;

        PacketLengths {
            protocol_footer_len,
            unencrypted_protocol_footer_len,
            enc_segment_len,
            enc_segment_end,
            payload_len,
            footer_start,
            footer_len,
            footer_end,
            digest_start,
            digest_end,
            num_digest_padding_bytes
        }
    }
}

const ZERO_PADDING: [u8;4] = [0u8;4];

fn authenticate_packet(buf: &[u8], lengths: &PacketLengths, last_seq: SeqNum, key: SymmetricKey) -> Option<SeqNum> {

    // if lengths.num_digest_padding_bytes != 0 {
    //     panic!("Num padding bytes non-zero: {:?}", lengths);
    // }
 
    let header_segment = &buf[HEADER_START..HEADER_END];
    let payload_segment = &buf[PAYLOAD_START..lengths.enc_segment_end];
    let footer_segment = &buf[lengths.footer_start..lengths.footer_end];
    let digest_segment = &buf[lengths.digest_start..lengths.digest_end];

    // probe up cur high word of seq, next high word of seq, and prev high word
    // of seq to test against sequence number rollover into high 16 bits
    for seq_num_offset in [0, 1, u16::MAX].iter() {
        let cur_hidden_seq = last_seq.high_word().wrapping_add(*seq_num_offset);

        let hidden_seq_bytes = cur_hidden_seq.to_le_bytes();

        let zero_padding_bytes= &ZERO_PADDING[..lengths.num_digest_padding_bytes];

        let computed_digest = sha1_hmac(&key.0, &[
            footer_segment,
            &hidden_seq_bytes,
            header_segment,
            &zero_padding_bytes[..lengths.num_digest_padding_bytes],
            payload_segment,
        ]);

        if crypto::util::fixed_time_eq(&computed_digest.0[..DIGEST_LEN], digest_segment) {
            let full_seq = SeqNum::from_high_low(cur_hidden_seq, &footer_segment[lengths.unencrypted_protocol_footer_len..]);

            return Some(full_seq)
        }
    }

    None
}

#[derive(Debug)]
pub enum KindParseError {
    UnknownOpcode(u8),
    TcpHeaderParseError,
}

#[derive(Debug)]
pub enum Kind<'a> {
    Control(ControlPacket<'a>),
    Tcp(TcpHeader),
}

impl<'a> Kind<'a> {
    pub fn from_packet(packet: &'a Packet) -> Result<(&'a Packet, Self), KindParseError> {
        use Opcode::*;
        match packet.header.opcode() {
            Some(Control) => {
                let (_, ctrl_packet) = ControlPacket::parse(&packet.payload()).unwrap();
                Ok((packet, Kind::Control(ctrl_packet)))
            }
            Some(Tcp2BytePort) => {
                let (_, header) = TcpHeader::parse_two_byte_port(packet.protocol_footer())
                    .map_err(|_| KindParseError::TcpHeaderParseError)?;

                Ok((packet, Kind::Tcp(header)))
            }
            _ => {
                Err(KindParseError::UnknownOpcode(packet.header.prefix))
            }
        }
    }
}

pub fn marshal_encrypt_and_sign_packet(
    opcode: Opcode,
    spi: SecurityParametersIndex,
    payload: &[u8],
    protocol_footer: &[u8],
    seq_num: SeqNum,
    keys: &TripleDesOneWayKeySet)
-> Option<Vec<u8>> {
    let header = Header::new(opcode, spi, payload.len());
    let mut buf = header.to_vec();

    let num_padding_bytes = if protocol_footer.len() >= header.encrypted_padding_len() {
        0
    } else {
        header.encrypted_padding_len() - protocol_footer.len()
    };

    let (high_seq, low_seq) = seq_num.high_low();

    for byte in payload {
        buf.push(*byte);
    }

    for _ in 0..num_padding_bytes {
        buf.push(0);
    }

    for byte in protocol_footer {
        buf.push(*byte);
    }

    buf.push(low_seq[0]);
    buf.push(low_seq[1]);

    let iv = seq_num.permute_iv(keys.iv);

    let encrypted_len = payload.len() + header.encrypted_padding_len();
    let encrypted_end = PAYLOAD_START + encrypted_len;

    {
        let encrypted_region = &mut buf[PAYLOAD_START..encrypted_end];
        tdes_cbc_encrypt_in_place(&keys.des, iv, encrypted_region)
            .map_err(|err|
                 error!("Error encrypting: {:?} {:?} {:?} {:02x?} {:02x?} {:x?} {:02x?} {} {} {}",
                    err,
                    opcode,
                    spi,
                    payload,
                    protocol_footer,
                    seq_num,
                    keys,
                    encrypted_len,
                    num_padding_bytes,
                    header.encrypted_padding_len()))
            .ok()?;
    }

    let footer_start = encrypted_end;
    let footer_len = buf.len() - footer_start;
    let footer_end = buf.len();

    let num_digest_padding_bytes = (4 - ((footer_len + HIDDEN_SEQ_NUM_LEN) % 4)) % 4;

    let computed_digest = {
        let header_segment = &buf[HEADER_START..HEADER_END];
        let payload_segment = &buf[PAYLOAD_START..encrypted_end];
        let footer_segment = &buf[footer_start..footer_end];

        sha1_hmac(&keys.sha.0, &[
            footer_segment,
            &high_seq,
            header_segment,
            &ZERO_PADDING[..num_digest_padding_bytes],
            payload_segment,
        ])
    };

    for byte in computed_digest.0[..DIGEST_LEN].iter() {
        buf.push(*byte);
    }

    Some(buf)
}

#[cfg(test)]
mod tests {
    use xbox_sys::crypto::DesIv;

    use crate::crypto::primitives::TripleDesKey;

    use super::*;

    use hex_literal::hex;

    #[test]
    fn decrypt_tcp_syn() {
        let buf = hex!["
            83 01 00 00

            f8 0d 25 11 51 fc 2f cd

            0b 7f a5 2b 00 00 00 00
            60 02 42 38
            
            06 00
            
            f0 d1 9e 5e 57 f3 1f c7 b7 54
        "];

        let last_seq_num = SeqNum(0x05);
        let expected_cur_seq_num = SeqNum(0x06);

        let expected_packet_lengths = PacketLengths {
            protocol_footer_len: 16,
            unencrypted_protocol_footer_len: 12,
            enc_segment_len: 8,
            enc_segment_end: 12,
            payload_len: 4,
            footer_start: 12,
            footer_len: 14,
            footer_end: 26,
            digest_start: 26,
            digest_end: 36,
            num_digest_padding_bytes: 0,
        };

        let keys = TripleDesOneWayKeySet {
            sha: SymmetricKey(hex!["e2 5f a9 2a c9 0f cb 43 87 45 56 f1 df ff b9 72"]),
            des: TripleDesKey(hex!["b3 68 64 8c 9b 20 31 83 7f 1f a7 70 83 52 d3 9b b9 52 b6 6d e5 07 b5 08"]),
            iv: DesIv(hex!["50 24 0b fe c6 c7 8c 00"]),
        };

        let header = Header::from_buffer(&buf).unwrap();

        let opcode = header.opcode().unwrap();

        assert_eq!(expected_packet_lengths, PacketLengths::new(buf.len(), &header, opcode));

        let cur_seq_num = authenticate_packet(&buf, &expected_packet_lengths, last_seq_num, keys.sha).unwrap();

        assert_eq!(expected_cur_seq_num, cur_seq_num);
    }

    #[test]
    fn decrypt_tcp_ack() {
        let buf = hex!["
            03 01 00 00
            04 00 00 69 0b 7f a5 2c d3 d5 7c ad 50 10 42 38
            07 00
            5f 71 ae 59 16 8f 01 b2 c8 d2
        "];

        let last_seq_num = SeqNum(0x06);
        let expected_cur_seq_num = SeqNum(0x07);

        let expected_packet_lengths = PacketLengths {
            protocol_footer_len: 16,
            unencrypted_protocol_footer_len: 16,
            enc_segment_len: 0,
            enc_segment_end: 4,
            payload_len: 0,
            footer_start: 4,
            footer_len: 18,
            footer_end: 22,
            digest_start: 22,
            digest_end: 32,
            num_digest_padding_bytes: 0,
        };

        let keys = TripleDesOneWayKeySet {
            sha: SymmetricKey(hex!["e2 5f a9 2a c9 0f cb 43 87 45 56 f1 df ff b9 72"]),
            des: TripleDesKey(hex!["b3 68 64 8c 9b 20 31 83 7f 1f a7 70 83 52 d3 9b b9 52 b6 6d e5 07 b5 08"]),
            iv: DesIv(hex!["50 24 0b fe c6 c7 8c 00"]),
        };

        let header = Header::from_buffer(&buf).unwrap();

        let opcode = header.opcode().unwrap();

        assert_eq!(expected_packet_lengths, PacketLengths::new(buf.len(), &header, opcode));

        let cur_seq_num = authenticate_packet(&buf, &expected_packet_lengths, last_seq_num, keys.sha).unwrap();

        assert_eq!(expected_cur_seq_num, cur_seq_num);
    }

    #[test]
    fn decrypt_tcp_psh() {
        let buf = hex!["
            c3 01 00 00 
            16 45 64 de c3 a0 3c c5 
            98 24 9b db 46 de 76 f7 
            d3 4a 47 dc 5b 6c fd 73 
            05 0b 08 58 31 18 4e 3c 
            15 38 d9 e0 ba 17 7a 46 
            b4 9e c0 e5 99 d6 13 35 
            8c b8 39 2f ef 33 7f 5d 
            93 12 30 5b 90 47 f2 bc 
            7f 6b 82 d5 32 58 00 28 
            3e a6 08 b2 7b af 3f 5b 
            57 02 e1 52 fc 13 33 91 
            28 97 9f ae 66 6b 0b 5f 
            00 bd 3b 51 1e 92 0d bb 
            c0 f2 89 bf 49 fd 61 1c 
            dd 8d 99 3d 19 09 3f 14 
            b3 c6 f2 87 4a 6f 92 27 
            2e 58 65 94 8a 1f c7 26 
            8c 44 1f 09 ed 7c bf 17 
            95 ec d9 df d2 2f 4b 33 
            75 03 ab c8 c0 9e 72 cd 
            93 4f 1f 98 3d 2d 58 11 
            fb 22 f5 51 4f 13 50 18 42 38 
            0b 00 
            ac e4 f5 4b 75 b1 2b 26 0d 7d
        "];

        let last_seq_num = SeqNum::new(0x0a);
        let expected_cur_seq_num = SeqNum::new(0x0b);

        let expected_packet_lengths = PacketLengths {
            protocol_footer_len: 16,
            unencrypted_protocol_footer_len: 10,
            enc_segment_len: 168,
            enc_segment_end: 172,
            payload_len: 162,
            footer_start: 172,
            footer_len: 12,
            footer_end: 184,
            digest_start: 184,
            digest_end: 194,
            num_digest_padding_bytes: 2,
        };

        let keys = TripleDesOneWayKeySet {
            sha: SymmetricKey(hex!["e3 3b c4 e3 f7 6c 34 72 3c 27 05 c3 fb aa 70 09"]),
            des: TripleDesKey(hex!["3b fd ab 70 6e fb 92 d3 3d 76 15 94 49 54 b0 7f b6 f7 5d e9 31 6d 54 23"]),
            iv: DesIv(hex!["a9 e6 9b 0d 5d 1d 4b f7"]),
        };

        let header = Header::from_buffer(&buf).unwrap();

        let opcode = header.opcode().unwrap();

        assert_eq!(expected_packet_lengths, PacketLengths::new(buf.len(), &header, opcode));

        let cur_seq_num = authenticate_packet(&buf, &expected_packet_lengths, last_seq_num, keys.sha).unwrap();

        assert_eq!(expected_cur_seq_num, cur_seq_num);
    }

    #[test]
    fn encrypt_tcp_psh() {
        let payload = hex!["
            48 54 54 50 2f 31 2e 30 20 32 30 30 20 4f 4b 0d
            0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a
            20 34 38 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70
            65 3a 20 78 6f 6e 2f 31 0d 0a 58 2d 45 72 72 3a
            20 30 0d 0a 0d 0a
        "];

        let protocol_footer = hex!["
            00 65 04 04 fd ec f8 a3 30 b9 ad 49 50 18 ff ff
        "];

        let keys = TripleDesOneWayKeySet {
            sha: SymmetricKey(hex!["e6 d8 53 03 3f 46 f8 ac db 10 b4 16 63 ae c4 db"]),
            des: TripleDesKey(hex!["a7 cb d3 fe d6 08 46 ba 4f c1 ae 67 e3 e0 f4 d5 a7 f1 e0 b9 92 23 04 b9"]),
            iv: DesIv(hex!["66 e3 26 69 11 26 dc 23"]),
        };

        let result = marshal_encrypt_and_sign_packet(
            Opcode::Tcp2BytePort,
            SecurityParametersIndex([20, 180, 0]),
            &payload,
            &protocol_footer,
            SeqNum(2),
            &keys);

        let expected_buf = hex!["
            43 14 b4 00 c9 b9 19 dd 8a 3d 60 40 c8 49 86 8e
            88 e9 bc 79 9b b7 4b 75 0c 94 f7 de 89 93 f8 a0
            2b a2 e8 fb c9 03 96 a8 07 40 f3 71 d2 74 12 e4
            a3 21 f8 1c 1f ba f6 2b 96 fb d4 b0 37 ed dd 5c
            2b 0c 5d c5 0a 4b 53 f3 89 95 07 bd 04 04 fd ec
            f8 a3 30 b9 ad 49 50 18 ff ff 02 00 d4 53 e3 3c
            f4 ea 14 d6 b1 f2
        "];

        assert_eq!(result, Some(expected_buf.to_vec()));

        let packet = Packet::decrypt_from(&expected_buf, SeqNum(1), &keys);

        packet.unwrap();
    }
}