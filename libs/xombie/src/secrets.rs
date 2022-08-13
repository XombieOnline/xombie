use hex_literal::hex;

use xbox_sys::crypto::SymmetricKey;

pub async fn get_sg_master_key(_sg_addr: [u8;4]) -> (SymmetricKey, Option<u32>) {
    (SymmetricKey(hex!["205cbb97cff0058123c22658fecd6898"]), None)
}