//! This module provides routines to encrypt/decrypt by using the RC4
//! algorithm with HMAC-MD5 required by RC4_HMAC
//!

mod encrypt;
pub use encrypt::{decrypt, encrypt};


mod key;
pub use key::{generate_key, generate_key_from_string};

mod preamble;
pub use preamble::generate_preamble;
