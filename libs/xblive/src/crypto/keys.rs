use hex_literal::hex;

use xbox_sys::crypto::SymmetricKey;

pub const HDD_MORPH_KEY: SymmetricKey =
    SymmetricKey(hex!["60 59 E8 2E DF BF 7F D3 23 35 74 2a 64 8B B1 2c"]);

pub const SIGNATURE_KEY: &[u8] = "signaturekey\0".as_bytes();

pub const DEVKIT_MACHINE_KEY: SymmetricKey =
    SymmetricKey(hex!["B2 74 D2 92 FE 16 A0 17 58 70 DB 61 7B 02 D0 AD"]);
