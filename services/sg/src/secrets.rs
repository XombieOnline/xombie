use hex_literal::hex;
use xblive::crypto::primitives::DiffieHellmanModulus;

const FIXED_SG_NONCE: [u8;8] = hex!["1d 87 44 40 8c 89 b1 13"];

const FIXED_DH_X: DiffieHellmanModulus = DiffieHellmanModulus(hex!["
    8bd371a22b8a5d5abe5ab715c481e456e3b655283fa40a3f
    8f9f970ced89d0b12dd8abb515fc14684d8dbc5d8c727de6
    3e178bb232c2f4192a0061aedbb0b7f8a6c88e344a431b1c
    4a78a19a501625046cbafa8c48662273db29c77402fa8ab3"]);

pub fn generate_sg_nonce() -> [u8;8] {
    FIXED_SG_NONCE
}

pub fn generate_dh_x() -> DiffieHellmanModulus {
    FIXED_DH_X
}
