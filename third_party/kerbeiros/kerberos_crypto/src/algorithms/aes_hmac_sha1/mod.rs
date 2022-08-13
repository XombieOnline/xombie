//! This module provides routines to encrypt/decrypt by using the AES
//! algorithm with HMAC-SHA1 required by AES128_CTS_HMAC_SHA1_96 and
//! AES256_CTS_HMAC_SHA1_96.

mod keys;
pub use keys::{
    generate_key, generate_key_from_string
};

mod decrypt;
pub use decrypt::{decrypt, encrypt};

mod preamble;
pub use preamble::generate_preamble;

mod salt;
pub use salt::generate_salt;
