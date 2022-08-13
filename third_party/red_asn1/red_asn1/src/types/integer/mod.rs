mod general;
mod int128;
mod int16;
mod int32;
mod int64;
mod int_trait;
mod uint32;

pub static INTEGER_TAG_NUMBER: u8 = 0x2;
/// Class to build/parse Integer ASN1
pub type Integer = i128;

pub use int_trait::Asn1Int;
