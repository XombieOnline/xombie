//! Useful internal functions

use rand::RngCore;


/// Generates an vector with random bytes
pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes: Vec<u8> = vec![0; size];
    rng.fill_bytes(&mut bytes);

    return bytes;
}

/// Helper to xorbytes of two arrays and produce a new one
pub fn xorbytes(v1: &[u8], v2: &[u8]) -> Vec<u8> {
    let mut v_xored = Vec::with_capacity(v1.len());

    for i in 0..v1.len() {
        v_xored.push(v1[i] ^ v2[i])
    }

    return v_xored;
}


pub fn string_unicode_bytes(s: &str) -> Vec<u8> {
    let s_utf16: Vec<u16> = s.encode_utf16().collect();
    return u16_array_to_le_bytes(&s_utf16);
}

pub fn u16_array_to_le_bytes(u16_array: &[u16]) -> Vec<u8> {
    let mut u8_vec: Vec<u8> = Vec::with_capacity(u16_array.len() * 2);

    for u16_item in u16_array.iter() {
        let u8_min = *u16_item as u8;
        let u8_max = (*u16_item >> 8) as u8;

        u8_vec.push(u8_min);
        u8_vec.push(u8_max);
    }

    return u8_vec;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u16_array_to_le_bytes() {
        assert_eq!(vec![0, 0], u16_array_to_le_bytes(&[0]));
        assert_eq!(vec![1, 0], u16_array_to_le_bytes(&[1]));
        assert_eq!(
            vec![9, 0, 8, 0, 7, 0, 6, 0],
            u16_array_to_le_bytes(&[9, 8, 7, 6])
        );
        assert_eq!(vec![0x15, 0x03], u16_array_to_le_bytes(&[789]));
        assert_eq!(vec![0x00, 0x01], u16_array_to_le_bytes(&[256]));
        assert_eq!(
            vec![0xd2, 0x04, 0xa5, 0x03, 0xbe, 0x6c],
            u16_array_to_le_bytes(&[1234, 933, 27838])
        );
    }
}
