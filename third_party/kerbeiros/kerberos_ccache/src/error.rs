//! Errors raised by this library

use failure::Fail;
use std::result;
use std::string::FromUtf8Error;
use kerberos_asn1;

/// Result to wrap kerbeiros error.
pub type ConvertResult<T> = result::Result<T, ConvertError>;

/// Type of error in kerbeiros library.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum ConvertError {
    /// Error handlening asn1 entities.
    #[fail(display = "Asn1 error: {}", _0)]
    Asn1Error(kerberos_asn1::Error),

    /// Invalid ascii string.
    #[fail(display = "Invalid ascii string")]
    InvalidAscii,

    /// Invalid utf8 string.
    #[fail(display = "Invalid utf8 string")]
    FromUtf8Error,

    /// No principal name
    #[fail(display = "No principal name found")]
    NoPrincipalName,

    /// No address found
    #[fail(display = "No address found")]
    NoAddress,

    /// Error parsing binary data
    #[fail(display = "Error parsing binary data")]
    BinaryParseError,


    /// The parsed struct doesn't have a required field.
    /// This could be due a Option field which is None.
    #[fail(display = "A required field is missing: {}", _0)]
    MissingField(String),

    #[fail(display = "KrbCredError: {}", _0)]
    KrbCredError(String)
}


impl From<FromUtf8Error> for ConvertError {
    fn from(_error: FromUtf8Error) -> Self {
        return Self::FromUtf8Error;
    }
}

impl From<kerberos_asn1::Error> for ConvertError {
    fn from(error: kerberos_asn1::Error) -> Self {
        return Self::Asn1Error(error);
    }
}

