use failure::Fail;
use std::result;

/// Result that encapsulates the Error type of this library
pub type Result<T> = result::Result<T, Error>;

/// Error raised by the routines of this library
#[derive(Fail, Clone, Debug, PartialEq)]
pub enum Error {
    /// Error while decrypting the data
    #[fail(display = "DecryptionError: {}", _0)]
    DecryptionError(String),

    /// Data is encrypted with an unsupported crypto algorithm
    #[fail(display = "UnsupportedAlgorithm: {}", _0)]
    UnsupportedAlgorithm(i32),

    /// Invalid key
    #[fail(
        display = "Invalid key: Only hexadecimal characters are allowed [1234567890abcdefABCDEF]"
    )]
    InvalidKeyCharset,

    /// Invalid key
    #[fail(display = "Invalid key: Length should be {}", _0)]
    InvalidKeyLength(usize),
}
