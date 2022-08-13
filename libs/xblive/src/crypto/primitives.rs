use block_modes::{Cbc, BlockMode};
use block_modes::block_padding::NoPadding;
use block_modes::cipher::generic_array::GenericArray;
use block_modes::cipher::generic_array::typenum::{U24, U8};

use bytes::BufMut;

use crypto::{
    hmac::Hmac,
    mac::Mac,
    md5::Md5,
    rc4::Rc4,
    sha1::Sha1,
    symmetriccipher::SynchronousStreamCipher};

use hex_literal::hex;

use num_bigint::BigUint;

use std::convert::TryInto;

use xbox_sys::crypto::DesIv;
use xbox_sys::codec::{BufPut, Decode, decode_array_u8};

pub const KEY_ID_LENGTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyId(pub [u8;KEY_ID_LENGTH]);

impl KeyId {
    pub const INVALID: KeyId = KeyId(hex!["00 00 00 00 00 00 00 00"]);
}

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for KeyId {
    fn put(&self, buf: &mut AnyBufMut) {
        buf.put_slice(&self.0)
    }
}

impl Decode for KeyId {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, val) = decode_array_u8(input)?;
        Ok((input, KeyId(val)))
    }
}

pub const DIFFIE_HELLMAN_MOD_LENGTH: usize = 96; //768 bits

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DiffieHellmanModulus(pub [u8;DIFFIE_HELLMAN_MOD_LENGTH]);

impl From<BigUint> for DiffieHellmanModulus {
    fn from(big: BigUint) -> Self {
        let mut big_vec = big.to_bytes_le();
        let num_padding_bytes = DIFFIE_HELLMAN_MOD_LENGTH - big_vec.len();
        for _ in 0..num_padding_bytes {
            big_vec.push(0);
        }
        DiffieHellmanModulus(big_vec.try_into().unwrap())
    }
}


pub const EMPTY_DIFFIE_HELLMAN_MODULUS: DiffieHellmanModulus = DiffieHellmanModulus([0u8;DIFFIE_HELLMAN_MOD_LENGTH]);

// RFC 2409 6.1 - First Oakley Default Group
// 2^768 - 2 ^704 - 1 + 2^64 * { [2^638 pi] + 149686 }
pub const FIRST_OAKLEY_GROUP_PRIME_BE: [u8;DIFFIE_HELLMAN_MOD_LENGTH] = hex!["
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF
"];

pub const FIRST_OAKLEY_GROUP_GENERATOR: u8 = 2;

pub struct DiffieHellmanResult {
    pub g_x: DiffieHellmanModulus,
    pub secret: DiffieHellmanModulus,
}

impl DiffieHellmanResult {
    pub fn new(dh_x: DiffieHellmanModulus, dh_g_y: DiffieHellmanModulus) -> Self {
        let big_generator = BigUint::from(FIRST_OAKLEY_GROUP_GENERATOR);
        let big_prime = BigUint::from_bytes_be(&FIRST_OAKLEY_GROUP_PRIME_BE);
    
        let big_x = BigUint::from_bytes_le(&dh_x.0);
    
        let big_g_x = big_generator.modpow(&big_x, &big_prime);

        let big_g_y = BigUint::from_bytes_le(&dh_g_y.0);
    
        let big_secret = big_g_y.modpow(&big_x, &big_prime);

        DiffieHellmanResult {
            g_x: DiffieHellmanModulus::from(big_g_x),
            secret: DiffieHellmanModulus::from(big_secret),
        }
    }
}

#[derive(Debug)]
pub enum BlockCryptError {
    Failed(block_modes::BlockModeError),
}

impl PartialEq for BlockCryptError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Failed(_), Self::Failed(_)) => true,
        }
    }
}

pub fn rc4_crypt_in_place(key: &[u8], data: &mut [u8]){
    let mut rc4 = Rc4::new(key);

    let input = data.to_vec();

    rc4.process(&input, data);
}

pub const SHA1_DIGEST_LEN: usize = 20;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha1Digest(pub [u8;SHA1_DIGEST_LEN]);

impl<AnyBufMut: BufMut> BufPut<AnyBufMut> for Sha1Digest {
    fn put(&self, buf: &mut AnyBufMut) {
        buf.put_slice(&self.0)
    }
}

impl Decode for Sha1Digest {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, val) = decode_array_u8(input)?;
        Ok((input, Sha1Digest(val)))
    }
}

pub fn sha1_hmac(key: &[u8], data: &[&[u8]]) -> Sha1Digest {
    let mut hmac = Hmac::new(Sha1::new(), key);
    for data in data {
        hmac.input(data);
    }

    let mut digest = Sha1Digest(Default::default());
    hmac.raw_result(&mut digest.0);

    digest
}

pub const MD5_DIGEST_LEN: usize = 16;
#[derive(Clone, Copy, Debug)]
pub struct Md5Digest(pub [u8;MD5_DIGEST_LEN]);

pub fn md5_hmac(key: &[u8], data: &[&[u8]]) -> Md5Digest {
    let mut hmac = Hmac::new(Md5::new(), key);
    for data in data {
        hmac.input(data);
    }

    let mut digest = Md5Digest(Default::default());
    hmac.raw_result(&mut digest.0);

    digest
}

/// Set the bottom bit in order to signify an odd number of 1 bits
fn set_des_parity_bit(byte: u8) -> u8 {
    let masked_byte = byte & 0b_1111_1110;
    if masked_byte.count_ones() & 1 == 0 {
        masked_byte | 0b_0000_0001
    } else {
        masked_byte & 0b_1111_1110
    }
}

pub const TRIPLE_DES_KEY_LEN: usize = 24;

#[derive(Clone, Debug, PartialEq)]
pub struct TripleDesKey(pub [u8;TRIPLE_DES_KEY_LEN]);

impl TripleDesKey {
    pub fn from_buf_with_invalid_parity(with_invalid_parity: &[u8]) -> TripleDesKey {
        let key_bytes = with_invalid_parity
            .iter()
            .map(|byte| set_des_parity_bit(*byte))
            .collect::<Vec<u8>>();

        TripleDesKey(key_bytes.try_into().unwrap())
    }
}

pub fn tdes_cbc_encrypt_in_place(key: &TripleDesKey, iv: DesIv, buf: &mut [u8]) -> Result<(), BlockCryptError> {
    let key = GenericArray::<u8, U24>::from_slice(&key.0);
    let iv = GenericArray::<u8, U8>::from_slice(&iv.0);

    let cipher = Cbc::<des::TdesEde3, NoPadding>::new_fix(&key, &iv);

    let _ = cipher.encrypt(buf, buf.len())
        .map_err(|err| BlockCryptError::Failed(err))?;

    Ok(())
}

pub fn tdes_cbc_decrypt_in_place(key: &TripleDesKey, iv: DesIv, buf: &mut [u8]) -> Result<(), BlockCryptError> {
    let key = GenericArray::<u8, U24>::from_slice(&key.0);
    let iv = GenericArray::<u8, U8>::from_slice(&iv.0);

    let cipher = Cbc::<des::TdesEde3, NoPadding>::new_fix(&key, &iv);

    let _ = cipher.decrypt(buf)
        .map_err(|err| BlockCryptError::Failed(err))?;

    Ok(())
}

pub fn verify_sha1_hmac<'a>(key: &[u8], payload: &'a[u8]) -> Option<&'a [u8]> {
    if payload.len() < SHA1_DIGEST_LEN {
        return None;
    }

    let payload_signature = &payload[..SHA1_DIGEST_LEN];

    let payload = &payload[SHA1_DIGEST_LEN..];

    let computed_signature = sha1_hmac(&key, &[payload]);

    if crypto::util::fixed_time_eq(&computed_signature.0, payload_signature) {
        Some(payload)
    } else {
        None
    }
}

const CONFOUNDER_LEN: usize = 8;
type Confounder = [u8;CONFOUNDER_LEN];

pub fn rc4_md5_hmac_encrypt(key: &[u8], nonce: u32, input: &[u8]) -> Vec<u8> {
    let confounder = rand::random::<Confounder>();
    rc4_md5_hmac_encrypt_reproducible(key, nonce, input, confounder)
}

fn rc4_md5_hmac_encrypt_reproducible(key: &[u8], nonce: u32, input: &[u8], confounder: Confounder) -> Vec<u8> {
    let state_key = md5_hmac(key, &[&nonce.to_le_bytes()]);

    let mut output = vec![];
    output.extend_from_slice(&[0u8;MD5_DIGEST_LEN]);
    output.extend_from_slice(&confounder);
    output.extend_from_slice(input);

    let checksum = md5_hmac(&state_key.0, &[&output[MD5_DIGEST_LEN..]]);

    output[0..MD5_DIGEST_LEN].copy_from_slice(&checksum.0);

    let local_key = md5_hmac(&state_key.0, &[&output[..MD5_DIGEST_LEN]]);

    let mut encrypted = vec![0u8;output.len() - MD5_DIGEST_LEN];

    let mut rc4 = Rc4::new(&local_key.0);
    rc4.process(&output[MD5_DIGEST_LEN..], &mut encrypted);
    output[MD5_DIGEST_LEN..].copy_from_slice(&encrypted);

    output
}

#[derive(Debug)]
pub enum Rc4HmacDecryptError {
    InputTooShort(usize),
    InvalidHmac,
}

pub fn rc4_md5_hmac_decrypt(key: &[u8], nonce: u32, input: &[u8]) -> Result<Vec<u8>, Rc4HmacDecryptError> {
    if input.len() <= MD5_DIGEST_LEN + CONFOUNDER_LEN {
        return Err(Rc4HmacDecryptError::InputTooShort(input.len()));
    }

    let checksum = &input[0..MD5_DIGEST_LEN];
    let ciphertext = &input[MD5_DIGEST_LEN..];

    let mut plaintext = vec![0u8;ciphertext.len()];

    let state_key = md5_hmac(key, &[&nonce.to_le_bytes()]);
    let local_key = md5_hmac(&state_key.0, &[checksum]);

    let mut rc4 = Rc4::new(&local_key.0);
    rc4.process(ciphertext, &mut plaintext);

    let calculated_checksum = md5_hmac(&state_key.0, &[&plaintext]);

    if !crypto::util::fixed_time_eq(&calculated_checksum.0, checksum) {
        return Err(Rc4HmacDecryptError::InvalidHmac);
    }

    // Strip confounder
    let mut result = vec![];
    result.extend_from_slice(&plaintext[CONFOUNDER_LEN..]);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::*;

    #[test]
    fn verify_client_version() {
        assert!(verify_sha1_hmac(
            &hex!["9e 4a be 82 d8 a9 61 8f e5 08 4a 57 e6 f7 c4 89"],
            &[245, 134, 78, 208, 181, 180, 83, 115, 165, 204, 210, 170, 35,
                201, 63, 22, 190, 153, 100, 17, 88, 98, 111, 120, 32, 86, 101,
                114, 115, 105, 111, 110, 61, 49, 46, 48, 48, 46, 53, 56, 52,
                57, 46, 51, 32, 84, 105, 116, 108, 101, 61, 48, 120, 70, 70,
                70, 69, 48, 48, 48, 48, 32, 84, 105, 116, 108, 101, 86, 101,
                114, 115, 105, 111, 110, 61, 52, 48, 56, 56, 53, 55, 56, 53,
                54, 0])
            .is_some())
    }

    #[test]
    fn rc4_md5_hmac_encrypt() {
        let input: [u8;28] = [
            0x30, 0x1a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30,
            0x32, 0x30, 0x30, 0x34, 0x31, 0x35, 0x30, 0x33,
            0x31, 0x37, 0x35, 0x32, 0x5a, 0xa1, 0x05, 0x02,
            0x03, 0x0e, 0x9a, 0x48];
        let message_type = 1;
        let confounder: Confounder = hex!["2A 8C E4 F6 FB 24 10 0E"];

        let ciphertext = rc4_md5_hmac_encrypt_reproducible(
            &crate::crypto::keys::DEVKIT_MACHINE_KEY.0,
            message_type,
            &input,
            confounder);

        assert_eq!(ciphertext, vec![
           0xb2, 0x23, 0x11, 0xa8, 0x6e, 0xd6, 0x13, 0x72,
           0x6b, 0x22, 0xd1, 0x8a, 0x89, 0x11, 0x33, 0x8a,
           0x11, 0x3f, 0xdc, 0xa1, 0xf1, 0x03, 0xa8, 0x48,
           0x40, 0x93, 0xfb, 0x5f, 0x23, 0x97, 0x8b, 0xb3,
           0x8a, 0xcc, 0xcf, 0xd4, 0xde, 0x82, 0x36, 0xb5,
           0x98, 0x73, 0x7f, 0xd7, 0x8d, 0xea, 0x4b, 0x0c,
           0x31, 0x8e, 0xb3, 0x47]);
    }

    #[test]
    fn rc4_md5_hmac_roundtrip() {
        let key = hex!["a7 80 a0 b4 83 7c 6a 64 74 3a b1 c0 48 02 83 68"];
        let nonce: u32 = 0xC;
        let confounder = hex!["f8 23 c4 17 02 54 67 c5"];
        let input = hex!["
            7b 43 30 41 a0 11 18 0f 32 30 32 32 30 31 31 31
            30 35 31 39 31 35 5a a1 05 02 03 03 34 50 a2 20
            30 1e a0 04 02 02 ff 7d a1 16 04 14 96 d7 53 51
            14 bb 6e bd 47 c4 1a a2 76 7e a6 93 a4 4d cb 01
            a3 03 02 01 00"];
        let expected_output = hex!["
            25 5a e6 33 81 96 91 b4 a4 c5 7d 51 33 9a 6b 45
            ce b5 73 4e ba ea 90 92 d7 42 e1 46 34 95 b5 1d
            3a c7 63 67 c2 b5 6a de 89 dc ee 1a ce 20 fb 8c
            b7 7f 44 2a 35 03 c3 72 d1 f5 86 ae 6b bb 5d 07
            ee 82 b2 e4 22 80 1c 69 20 f5 df 3d 40 5c 66 8f
            31 3d b3 4a f1 d7 8d 13 c5 bb 55 b1 03"];
        
        let output = rc4_md5_hmac_encrypt_reproducible(&key, nonce, &input, confounder);

        assert_eq!(&expected_output, output.as_slice());

        let decrypted_input = rc4_md5_hmac_decrypt(&key, nonce, &output)
            .unwrap();
        
        assert_eq!(&input, decrypted_input.as_slice())
    }

    #[test]
    fn des_key_parity() {
        // All permutations of a byte should have an odd number of bits set
        for i in 0..=0xFF {
            assert_eq!(set_des_parity_bit(i).count_ones() & 1, 1);
        }
    }

    #[test]
    fn tdes_cbc_enc_in_place() {
        let mut buffer = hex!["
            53 65 63 72 65 74 20 73
            74 72 69 6e 67 00 00 00
            00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00
        "];

        let key = TripleDesKey::from_buf_with_invalid_parity(&hex!["
            10 11 12 13 14 15 16 17
            20 21 22 23 24 25 26 27
            30 31 32 33 34 35 36 37"]
        );

        let iv = DesIv(hex!["CC CC CC CC CC CC CC CC"]);

        super::tdes_cbc_encrypt_in_place(&key, iv, &mut buffer).unwrap();

        assert_eq!(buffer, hex!["
            57 c6 d4 85 e4 95 76 db
            88 4f b6 ea 03 a2 03 13
            6b 0e 20 f1 bd 24 0b c6
            56 c9 99 88 10 24 7e 1c
            86 f6 63 5f 95 6b 0e 3d
        "]);
    }
}