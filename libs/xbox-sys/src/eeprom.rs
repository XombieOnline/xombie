use crate::crypto::SYMMETRIC_KEY_LEN;
use crate::std::convert::TryInto;

use crate::config::*;
use crate::crypto::SymmetricKey;

pub const LEN: usize = 256;

pub const SERIAL_NUBMER_OFFSET: usize = 0x34;
pub const SERIAL_NUBMER_END: usize = SERIAL_NUBMER_OFFSET + SERIAL_NUBMER_LEN;

pub const MAC_ADDRESS_OFFSET: usize = 0x40;
pub const MAC_ADDRESS_END: usize = MAC_ADDRESS_OFFSET + MAC_ADDRESS_LEN;

pub const ONLINE_KEY_OFFSET: usize = 0x48;
pub const ONLINE_KEY_END: usize = ONLINE_KEY_OFFSET + SYMMETRIC_KEY_LEN;

#[derive(Debug)]
pub struct Eeprom {
    bytes: [u8;LEN],
}

#[derive(Debug, PartialEq)]
pub enum EepromNewError {
    InccorectBufferSize
}

impl Eeprom {
    pub fn from_buf(buf: &[u8]) -> Result<Eeprom, EepromNewError> {
        if buf.len() != LEN {
            return Err(EepromNewError::InccorectBufferSize)
        }

        Ok(Eeprom {
            // Unwrap is ok because above len check
            bytes: buf.try_into().unwrap(),
        })
    }

    pub fn mac_address(&self) -> MacAddress {
        MacAddress(
            // Unwrap ok, because fixed size buffer in src and dst
            self.bytes[MAC_ADDRESS_OFFSET..MAC_ADDRESS_END].try_into().unwrap(),
        )
    }

    pub fn serial_number(&self) -> SerialNumber {
        SerialNumber(
            // Unwrap ok, because fixed size buffer in src and dst
            self.bytes[SERIAL_NUBMER_OFFSET..SERIAL_NUBMER_END].try_into().unwrap(),
        )
    }

    pub fn online_key(&self) -> SymmetricKey {
        SymmetricKey(
            // Unwrap ok, because fixed size buffer in src and dst
            self.bytes[ONLINE_KEY_OFFSET..ONLINE_KEY_END].try_into().unwrap(),
        )
    }
}
