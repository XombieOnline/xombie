use hex_literal::hex;

use super::{SymmetricKey, DesIv};

pub const V_1_0_EEPROM_KEY: SymmetricKey =
    SymmetricKey(hex!["2a3bad2cb1944f93aacdcd7e0ac2ee5a"]);

pub const MU_USER_ACCOUNT_IV: DesIv =
	DesIv(hex!["7b35a8b727ed437a"]);

pub const MU_USER_ACCOUNT_DES_SEED: SymmetricKey =
	SymmetricKey(hex!["a714213d94461e05976de835212ae57c"]);

pub const MU_USER_ACCOUNT_SIGNATURE_KEY: SymmetricKey =
	SymmetricKey(hex!["62bd92b64f458470d3ff4f223c6ee7ea"]);

pub const USER_ACCOUNT_DES_SEED_KEY_0: SymmetricKey =
	SymmetricKey(hex!["2bb8d9efd2046d9d1f39b15b465801d7"]);

pub const USER_ACCOUNT_DES_SEED_KEY_1: SymmetricKey =
	SymmetricKey(hex!["1e05d73aa4206a7ba05bcddfad26d3de"]);
