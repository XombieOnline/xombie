use std::sync::atomic::AtomicU32;

use xbox_sys::crypto::DesIv;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SeqNum(pub u32);

impl SeqNum {
    pub fn new(i: u32) -> Self {
        SeqNum(i)
    }

    pub fn from_high_low(high: u16, low: &[u8]) -> Self {
        Self(
            low[0] as u32 | ((low[1] as u32) << 8) | ((high as u32) << 16)
        )
    }

    pub fn high_word(&self) -> u16 {
        (self.0 >> 16) as u16
    }

    pub fn high_low(&self) -> ([u8;2], [u8;2]) {
        let bytes = self.0.to_le_bytes();

        ([bytes[2], bytes[3]], [bytes[0], bytes[1]])
    }

    pub fn permute_iv(&self, orig_iv: DesIv) -> DesIv {
        const LOW_WORD_MASK: u64 = 0x00000000_FFFFFFFF;

        let seq_64 = self.0 as u64;
        let orig_iv_64 = u64::from_le_bytes(orig_iv.0);
        let orig_iv_lo = orig_iv_64 & LOW_WORD_MASK;
        let orig_iv_hi = orig_iv_64 >> 32;

        let full_lo = orig_iv_lo * seq_64;
        let full_hi = orig_iv_hi * seq_64;

        let out_iv_lo = (full_lo ^ (full_hi >> 32)) & LOW_WORD_MASK;
        let out_iv_hi = (full_hi ^ (full_lo >> 32)) & LOW_WORD_MASK; 

        let out_iv_word = out_iv_lo | (out_iv_hi << 32);

        DesIv(out_iv_word.to_le_bytes())
    }
}

#[derive(Debug)]
pub struct SeqNumGenerator {
    next: AtomicU32,
}

impl SeqNumGenerator {
    pub fn new() -> Self {
        SeqNumGenerator {
            next: AtomicU32::new(1),
        }
    }

    pub fn next(&self) -> SeqNum {
        let mut cur = self.next.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        // Skip SeqNum(0) as it permutes IV to [0u8;8]
        if cur == 0 {
            cur = self.next.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }

        SeqNum(cur)
    }
}
