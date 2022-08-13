use crate::cryptography::{encrypt_aes_cbc, AesSizes};
use num::Integer;

pub fn dk(key: &[u8], constant: &[u8], aes_sizes: &AesSizes) -> Vec<u8> {
    let mut plaintext = n_fold(constant, aes_sizes.block_size());
    let mut result: Vec<u8> = Vec::new();

    while result.len() < aes_sizes.seed_size() {
        plaintext = encrypt_aes_cbc(key, &plaintext, aes_sizes);
        result.append(&mut plaintext.clone());
    }

    return result;
}

pub fn n_fold(v: &[u8], nbytes: usize) -> Vec<u8> {
    let data_13_series = generate_13_bits_rotations_serie(v, nbytes);
    let nbytes_chunks = divide_in_exact_n_bytes_chunks(&data_13_series, nbytes);
    return add_chunks_with_1s_complement_addition(&nbytes_chunks);
}

fn generate_13_bits_rotations_serie(v: &[u8], nbytes: usize) -> Vec<u8> {
    let least_common_multiple = nbytes.lcm(&v.len());
    let mut big_v: Vec<u8> = Vec::new();

    for i in 0..(least_common_multiple / v.len()) {
        let mut v_rotate = rotate_rigth_n_bits(v, 13 * i);
        big_v.append(&mut v_rotate);
    }

    return big_v;
}

fn rotate_rigth_n_bits(v: &[u8], nbits: usize) -> Vec<u8> {
    let nbytes = nbits / 8 % v.len();
    let nbits_remain = nbits % 8;

    let mut v_rotate: Vec<u8> = Vec::with_capacity(v.len());

    for i in 0..v.len() {
        let index_a = (((i as i32 - nbytes as i32) % v.len() as i32)
            + v.len() as i32) as usize
            % v.len();
        let index_b = (((i as i32 - nbytes as i32 - 1) % v.len() as i32)
            + v.len() as i32) as usize
            % v.len();

        v_rotate.push(
            (((v[index_a] as u16) >> nbits_remain) as u8)
                | (((v[index_b] as u16) << (8 - nbits_remain)) as u8),
        );
    }

    return v_rotate;
}

fn divide_in_exact_n_bytes_chunks(v: &[u8], nbytes: usize) -> Vec<Vec<u8>> {
    let mut nbytes_chunks: Vec<Vec<u8>> = Vec::new();

    let mut i = 0;
    while i < v.len() {
        nbytes_chunks.push(v[i..i + nbytes].to_vec());
        i += nbytes;
    }

    return nbytes_chunks;
}

fn add_chunks_with_1s_complement_addition(chunks: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut result = chunks[0].clone();
    for chunk in chunks[1..].iter() {
        result = add_chunk_with_1s_complement(&result, chunk);
    }
    return result;
}

fn add_chunk_with_1s_complement(
    chunk_1: &Vec<u8>,
    chunk_2: &Vec<u8>,
) -> Vec<u8> {
    let mut tmp_add = add_chunks_as_u16_vector(chunk_1, chunk_2);

    while tmp_add.iter().any(|&x| x > 0xff) {
        propagate_carry_bits(&mut tmp_add);
    }

    return convert_u16_vector_to_u8_vector(&tmp_add);
}

fn add_chunks_as_u16_vector(chunk_1: &Vec<u8>, chunk_2: &Vec<u8>) -> Vec<u16> {
    let mut tmp_add: Vec<u16> = vec![0; chunk_1.len()];

    for j in 0..chunk_1.len() {
        tmp_add[j] = chunk_1[j] as u16 + chunk_2[j] as u16;
    }

    return tmp_add;
}

fn propagate_carry_bits(tmp_add: &mut Vec<u16>) {
    let mut aux_vector: Vec<u16> = vec![0; tmp_add.len()];

    for i in 0..tmp_add.len() {
        let index = (((i as i32 - tmp_add.len() as i32 + 1)
            % tmp_add.len() as i32)
            + tmp_add.len() as i32) as usize
            % tmp_add.len();
        aux_vector[i] = (tmp_add[index] >> 8) + (tmp_add[i] & 0xff)
    }
    for i in 0..tmp_add.len() {
        tmp_add[i] = aux_vector[i];
    }
}

fn convert_u16_vector_to_u8_vector(v: &Vec<u16>) -> Vec<u8> {
    return v.iter().map(|&x| x as u8).collect();
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_n_fold() {
        assert_eq!(
            vec![0xbe, 0x07, 0x26, 0x31, 0x27, 0x6b, 0x19, 0x55],
            n_fold("012345".as_bytes(), 8)
        );

        assert_eq!(
            vec![0x78, 0xa0, 0x7b, 0x6c, 0xaf, 0x85, 0xfa],
            n_fold("password".as_bytes(), 7)
        );

        assert_eq!(
            vec![0xbb, 0x6e, 0xd3, 0x08, 0x70, 0xb7, 0xf0, 0xe0],
            n_fold("Rough Consensus, and Running Code".as_bytes(), 8)
        );

        assert_eq!(
            vec![
                0x59, 0xe4, 0xa8, 0xca, 0x7c, 0x03, 0x85, 0xc3, 0xc3, 0x7b,
                0x3f, 0x6d, 0x20, 0x00, 0x24, 0x7c, 0xb6, 0xe6, 0xbd, 0x5b,
                0x3e
            ],
            n_fold("password".as_bytes(), 21)
        );

        assert_eq!(
            vec![
                0xdb, 0x3b, 0x0d, 0x8f, 0x0b, 0x06, 0x1e, 0x60, 0x32, 0x82,
                0xb3, 0x08, 0xa5, 0x08, 0x41, 0x22, 0x9a, 0xd7, 0x98, 0xfa,
                0xb9, 0x54, 0x0c, 0x1b
            ],
            n_fold("MASSACHVSETTS INSTITVTE OF TECHNOLOGY".as_bytes(), 24)
        );

        assert_eq!(
            vec![
                0x51, 0x8a, 0x54, 0xa2, 0x15, 0xa8, 0x45, 0x2a, 0x51, 0x8a,
                0x54, 0xa2, 0x15, 0xa8, 0x45, 0x2a, 0x51, 0x8a, 0x54, 0xa2,
                0x15
            ],
            n_fold("Q".as_bytes(), 21)
        );

        assert_eq!(
            vec![
                0xfb, 0x25, 0xd5, 0x31, 0xae, 0x89, 0x74, 0x49, 0x9f, 0x52,
                0xfd, 0x92, 0xea, 0x98, 0x57, 0xc4, 0xba, 0x24, 0xcf, 0x29,
                0x7e
            ],
            n_fold("ba".as_bytes(), 21)
        );

        assert_eq!(
            vec![0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73],
            n_fold("kerberos".as_bytes(), 8)
        );

        assert_eq!(
            vec![
                0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73, 0x7b, 0x9b,
                0x5b, 0x2b, 0x93, 0x13, 0x2b, 0x93
            ],
            n_fold("kerberos".as_bytes(), 16)
        );

        assert_eq!(
            vec![
                0x83, 0x72, 0xc2, 0x36, 0x34, 0x4e, 0x5f, 0x15, 0x50, 0xcd,
                0x07, 0x47, 0xe1, 0x5d, 0x62, 0xca, 0x7a, 0x5a, 0x3b, 0xce,
                0xa4
            ],
            n_fold("kerberos".as_bytes(), 21)
        );

        assert_eq!(
            vec![
                0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73, 0x7b, 0x9b,
                0x5b, 0x2b, 0x93, 0x13, 0x2b, 0x93, 0x5c, 0x9b, 0xdc, 0xda,
                0xd9, 0x5c, 0x98, 0x99, 0xc4, 0xca, 0xe4, 0xde, 0xe6, 0xd6,
                0xca, 0xe4
            ],
            n_fold("kerberos".as_bytes(), 32)
        );
    }
}
