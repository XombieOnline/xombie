use crate::std::fmt;

pub const MAC_ADDRESS_LEN: usize = 6;

#[derive(Debug)]
pub struct MacAddress(pub [u8;MAC_ADDRESS_LEN]);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            self.0[0], self.0[1], self.0[2],
            self.0[3], self.0[4], self.0[5])
    }
}

pub const SERIAL_NUBMER_LEN: usize = 12;

#[derive(Debug, PartialEq)]
pub struct SerialNumber(pub [u8;SERIAL_NUBMER_LEN]);

impl SerialNumber {
    pub fn is_format_valid(&self) -> bool {
        for byte in self.0 {
            if !(byte as char).is_ascii_digit() {
                return false
            }
        }

        true
    }

    pub fn as_str<'a>(&'a self) -> Option<&'a str> {
        if self.is_format_valid() {
            crate::std::str::from_utf8(&self.0).ok()
        } else {
            None
        }
    }

    pub fn parse(s: &str) -> Option<SerialNumber> {
        let mut serial_number = SerialNumber([0;SERIAL_NUBMER_LEN]);
        let mut highest_i = 0;
        for (i, c) in s.char_indices() {
            if i >= SERIAL_NUBMER_LEN {
                return None;
            }
            if !c.is_digit(10) {
                return None;
            }
            highest_i = i;
            serial_number.0[i] = c as u8;
        }

        if highest_i != (SERIAL_NUBMER_LEN - 1) {
            return None;
        }

        Some(serial_number)
    }
}

impl fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "{}", s),
            None => write!(f, "{:02x?}", self)
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn parse_serial() {
        assert_eq!(SerialNumber::parse("801735999216"),
            Some(SerialNumber(hex!["38 30 31 37 33 35 39 39 39 32 31 36"])));
    }
}
