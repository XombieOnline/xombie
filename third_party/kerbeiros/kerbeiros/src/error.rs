//! Errors raised by this library

use ascii::FromAsciiError;
use failure::Fail;
use kerberos_crypto;
use kerberos_ccache;
use std::result;
use std::string::FromUtf8Error;
use crate::messages::{KrbError, AsRep};
use kerberos_asn1;

/// Result to wrap kerbeiros error.
pub type Result<T> = result::Result<T, Error>;

/// Type of error in kerbeiros library.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    /// Error handlening asn1 entities.
    #[fail(display = "Asn1 error: {}", _0)]
    Asn1Error(kerberos_asn1::Error),

    /// Error produced in the application of cryptographic algorithms.
    #[fail(display = "Cryptography error: {}", _0)]
    CryptographyError(kerberos_crypto::Error),

    /// Invalid ascii string.
    #[fail(display = "Invalid ascii string")]
    InvalidAscii,

    /// Invalid utf8 string.
    #[fail(display = "Invalid utf-8 string")]
    InvalidUtf8,

    /// Invalid microseconds value. Minimum = 0, Maximum = 999999.
    #[fail(display = "Invalid microseconds value {}. Max is 999999", _0)]
    InvalidMicroseconds(u32),

    /// Error in i/o operation.
    #[fail(display = "Error in i/o operation")]
    IOError,

    /// Invalid key
    #[fail(
        display = "Invalid key: Only hexadecimal characters are allowed [1234567890abcdefABCDEF]"
    )]
    InvalidKeyCharset,

    /// Invalid key
    #[fail(display = "Invalid key: Length should be {}", _0)]
    InvalidKeyLength(usize),

    /// Received KRB-ERROR response.
    #[fail(display = "Received {:?}", _0)]
    KrbErrorResponse(KrbError),

    /// Error resolving name.
    #[fail(display = "Error resolving name: {}", _0)]
    NameResolutionError(String),

    /// Error sending/receiving data over the network.
    #[fail(display = "Network error")]
    NetworkError,

    /// No key was provided in order to decrypt the KDC response.
    #[fail(display = "No key was provided")]
    NoKeyProvided,

    /// None cipher algorithm supported was specified.
    #[fail(display = "None cipher algorithm supported was specified")]
    NoProvidedSupportedCipherAlgorithm,

    /// Some necessary data was not available in order to build the required message.
    #[fail(display = "Not available data {}", _0)]
    NotAvailableData(String),

    /// Error parsing AS-REP message.
    #[fail(display = "Error parsing AsRep: {}", _1)]
    ParseAsRepError(AsRep, Box<Error>),

    /// The type of the principal name was not specified.
    #[fail(display = "Undefined type of principal name: {}", _0)]
    PrincipalNameTypeUndefined(String),

    /// No principal name
    #[fail(display = "No principal name found")]
    NoPrincipalName,

    /// No address found
    #[fail(display = "No address found")]
    NoAddress,

    /// Error parsing binary data
    #[fail(display = "Error parsing binary data")]
    BinaryParseError,
}

impl From<kerberos_crypto::Error> for Error {
    fn from(kind: kerberos_crypto::Error) -> Error {
        return Self::CryptographyError(kind);
    }
}

impl From<FromAsciiError<&str>> for Error {
    fn from(_error: FromAsciiError<&str>) -> Self {
        return Self::InvalidAscii;
    }
}

impl From<FromAsciiError<Vec<u8>>> for Error {
    fn from(_error: FromAsciiError<Vec<u8>>) -> Self {
        return Self::InvalidAscii;
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_error: FromUtf8Error) -> Self {
        return Self::InvalidUtf8;
    }
}

impl From<kerberos_asn1::Error> for Error {
    fn from(error: kerberos_asn1::Error) -> Self {
        return Self::Asn1Error(error);
    }
}

impl<E> From<kerberos_ccache::Error<E>> for Error {
    fn from(_error: kerberos_ccache::Error<E>) -> Self {
        return Self::BinaryParseError;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kerberos_error() {
        match produce_invalid_network_error() {
            Err(kerberos_error) => match kerberos_error {
                Error::NetworkError => {}
                _ => {
                    unreachable!();
                }
            },
            _ => {
                unreachable!()
            }
        }
    }

    fn produce_invalid_network_error() -> Result<()> {
        Err(Error::NetworkError)?;
        unreachable!();
    }
}
