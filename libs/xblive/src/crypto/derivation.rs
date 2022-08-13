use std::collections::VecDeque;
use std::convert::TryInto;

use xbox_sys::crypto::{DES_IV_LEN, DesIv};

use crate::crypto::primitives::{DiffieHellmanModulus, Md5Digest, TripleDesKey, TRIPLE_DES_KEY_LEN, md5_hmac, rc4_crypt_in_place, sha1_hmac};
use crate::crypto::keys::{HDD_MORPH_KEY, SIGNATURE_KEY};
use crate::sg::SgNonce;

use crypto::{
    digest::Digest,
    md5::Md5};

use xbox_sys::crypto::{SYMMETRIC_KEY_LEN, SymmetricKey};
    
pub fn generate_machine_key(hdd_key: SymmetricKey, online_key: SymmetricKey) -> SymmetricKey {
    let digest = sha1_hmac(&HDD_MORPH_KEY.0, &[&hdd_key.0]);

    let mut machine_key = SymmetricKey(online_key.0);

    rc4_crypt_in_place(&digest.0, &mut machine_key.0);

    machine_key
}

pub fn generate_nonce_hmac_key(session_key: SymmetricKey, nonce: u32) -> SymmetricKey {
    permute_key_with_md5(
        &session_key.0,
        &nonce.to_le_bytes(),
        1026,
    )
}

pub fn generate_compound_identity_key(client_key: SymmetricKey, session_key: SymmetricKey) -> SymmetricKey {
    permute_key_with_md5(
        &client_key.0,
        &session_key.0,
        1024,
    )
}

fn permute_key_with_md5(key_1: &[u8], key_2: &[u8], salt: u32) -> SymmetricKey {
    let derived_key_1 = md5_hmac(key_1, &[SIGNATURE_KEY]);

    let mut md5 = Md5::new();
    md5.input(&salt.to_le_bytes());
    md5.input(key_2);

    let mut derived_key_2 = Md5Digest(Default::default());
    md5.result(&mut derived_key_2.0);

    SymmetricKey(md5_hmac(&derived_key_1.0, &[&derived_key_2.0]).0)
}

#[derive(Clone, Debug, PartialEq)]
pub struct TripleDesOneWayKeySet {
    pub sha: SymmetricKey,
    pub des: TripleDesKey,
    pub iv: DesIv,
}

#[derive(Debug, PartialEq)]
pub struct TripleDesConnectionKeySet {
    pub key: SymmetricKey,
    pub dh_secret: DiffieHellmanModulus,
    pub client_to_sg_nonce: SgNonce,
    pub sg_to_client_nonce: SgNonce,
    pub client_to_sg: TripleDesOneWayKeySet,
    pub sg_to_client: TripleDesOneWayKeySet,
}

impl TripleDesConnectionKeySet {
    pub fn generate(
        key: SymmetricKey,
        dh_secret: DiffieHellmanModulus,
        client_to_sg_nonce: SgNonce,
        sg_to_client_nonce: SgNonce)
    -> Self {
        let mut keystream = VecDeque::new();

        // Each of the five iterations adds i to the low u32 le of the dh secret to 
        // expand the size of the hash 5x
        let dh_orig_low_u32 = u32::from_le_bytes(dh_secret.0[..4].try_into().unwrap());
    
        for i in 0..5 {
            let low_word_bytes = dh_orig_low_u32
                .wrapping_add(i)
                .to_le_bytes();
    
            let digest = sha1_hmac(&key.0, &[
                &low_word_bytes,
                &dh_secret.0[4..],
                &client_to_sg_nonce.0,
                &sg_to_client_nonce.0,
            ]);
    
            for byte in digest.0.iter() {
                keystream.push_back(*byte);
            }
        }
    
        let sha_client_to_sg: SymmetricKey = SymmetricKey(keystream.drain(..SYMMETRIC_KEY_LEN).collect::<Vec<u8>>().try_into().unwrap());
        let des_client_to_sg: TripleDesKey = TripleDesKey::from_buf_with_invalid_parity(
            &keystream.drain(..TRIPLE_DES_KEY_LEN).collect::<Vec<u8>>());
    
        let sha_sg_to_client: SymmetricKey = SymmetricKey(keystream.drain(..SYMMETRIC_KEY_LEN).collect::<Vec<u8>>().try_into().unwrap());
        let des_sg_to_client: TripleDesKey = TripleDesKey::from_buf_with_invalid_parity(
            &keystream.drain(..TRIPLE_DES_KEY_LEN).collect::<Vec<u8>>());
    
        let iv_client_to_sg: DesIv = DesIv(keystream.drain(..DES_IV_LEN).collect::<Vec<u8>>().try_into().unwrap());
        let iv_sg_to_client: DesIv = DesIv(keystream.drain(..DES_IV_LEN).collect::<Vec<u8>>().try_into().unwrap());
    
        TripleDesConnectionKeySet {
            key,
            dh_secret,
            client_to_sg_nonce,
            sg_to_client_nonce,
    
            sg_to_client: TripleDesOneWayKeySet {
                sha: sha_sg_to_client,
                des: des_sg_to_client,
                iv: iv_sg_to_client,
            },
    
            client_to_sg: TripleDesOneWayKeySet {
                sha: sha_client_to_sg,
                des: des_client_to_sg,
                iv: iv_client_to_sg,
            },
        }    
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use xbox_sys::crypto::SymmetricKey;

    use crate::crypto::keys::DEVKIT_MACHINE_KEY;

    use hex_literal::hex;

    const TEST_HDD_KEY: SymmetricKey =
        SymmetricKey(hex!["f8 d4 86 3c ac 0e da 58 81 3b 7a 6d 4a 7e b4 a3"]);

    const TEST_ONLINE_KEY: SymmetricKey =
        SymmetricKey(hex!["1c 3c a4 bb 85 a4 b2 58 a0 a6 3a 14 97 8c a0 55"]);

    const TEST_MACHINE_KEY: SymmetricKey =
        SymmetricKey(hex!["ad ab 55 2f f9 e4 5e 47 9c 7f 92 46 19 e9 62 bd"]);

    #[test]
    fn machine_key() {
        assert_eq!(generate_machine_key(TEST_HDD_KEY, TEST_ONLINE_KEY),
            TEST_MACHINE_KEY);
    }

    #[test]
    fn nonce_hmac_key() {
        assert_eq!(generate_nonce_hmac_key(DEVKIT_MACHINE_KEY, 0),
            SymmetricKey(hex!["2a 6b ad e5 1f f5 dd 3f 77 de 26 ed 2b 2a 8a 62"]));

        assert_eq!(generate_nonce_hmac_key(
                SymmetricKey(hex!["75 5d 72 fc 34 c4 93 90 1e a6 e8 e3 dd 3f ab 75"]),
                0x0b9bd8d3),
            SymmetricKey(hex!["d8 5e f7 e8 90 18 ef fb b5 bb b9 c3 cd cb fc 95"]))
    }

    #[test]
    fn sg_triple_des_connection_key_set() {
        let key = SymmetricKey(hex!["31 33 59 b8 ac b3 44 b9 98 1e 6b e2 c5 5f b5 1c"]);

        let dh_secret = DiffieHellmanModulus(hex!["
            95 34 19 df 3f fe 6d da ca 2a 09 bd 4a 4b 96 8f
            84 ed a8 7c 60 2d 84 aa 16 90 5c d1 c9 b2 47 de
            56 6e 77 54 e8 1e 14 a9 b1 49 ce 33 c7 7c f3 63
            c7 c8 c3 cb 30 90 95 27 60 bc c7 76 f9 8b 13 e5
            45 0a bd 3a 73 12 2f e4 30 ba 32 b0 b2 cf 12 6e
            e7 03 ee 5c 42 fa d6 d8 c6 e4 c5 84 06 64 3b 49
        "]);

        let client_to_sg_nonce = SgNonce(hex!["7f 53 f5 de de e8 82 97"]);

        let sg_to_client_nonce = SgNonce(hex!["1d 87 44 40 8c 89 b1 13"]);

        let key_set = TripleDesConnectionKeySet::generate(
            key,
            dh_secret,
            client_to_sg_nonce,
            sg_to_client_nonce
        );

        assert_eq!(key_set, TripleDesConnectionKeySet {
            key,
            dh_secret,
            client_to_sg_nonce,
            sg_to_client_nonce,

            sg_to_client: TripleDesOneWayKeySet {
                sha: SymmetricKey(hex!["DA 0C 47 81 4D 99 57 75 24 82 59 D2 73 0B 00 82"]),
                des: TripleDesKey(hex!["BC 9D E0 D5 76 C4 AD 58 BA 31 20 32 75 52 7A 3D F8 D3 80 8A F2 58 CD EF"]),
                iv: DesIv(hex!["E1 25 78 D9 75 D3 37 25"]),
            },

            client_to_sg: TripleDesOneWayKeySet {
                sha: SymmetricKey(hex!["D4 D3 24 4F 96 2C B8 51 F7 E6 DA 57 1F B0 3E 2A"]),
                des: TripleDesKey(hex!["52 10 2F D0 4C E6 C2 10 13 8C 85 5B E0 08 0D 2A F7 D5 61 F2 52 10 A2 0B"]),
                iv: DesIv(hex!["64 A6 58 95 AB 73 D8 4E"]),
            },

        })
    }

    #[test]
    fn compound_identity_key() {
        const CLIENT_KEY: SymmetricKey = SymmetricKey(
            hex!["62 a6 a3 cd 3c e6 31 eb 8e 95 1f bb 88 02 1e 42"]
        );

        const SESSION_KEY: SymmetricKey = SymmetricKey(
            hex!["09 2c 5b 22 e5 e2 69 c4 6d 0b f7 63 86 ab 1c ca"]
        );

        const EXPECTED_COMPOUND_IDENTITY_KEY: SymmetricKey = SymmetricKey(
            hex!["95 00 ed c8 df 6a cf 13 b1 de cd 7e 8c d2 be 7e"]
        );

        assert_eq!(EXPECTED_COMPOUND_IDENTITY_KEY,
            generate_compound_identity_key(CLIENT_KEY, SESSION_KEY));
    }

}