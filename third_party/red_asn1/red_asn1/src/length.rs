use crate::error::{Error, Result};
use nom::number::complete::be_u8;

pub fn build_length(value_size: usize) -> Vec<u8> {
    if value_size < 128 {
        return vec![value_size as u8];
    }

    let mut shifted_length = value_size;
    let mut octets_count: u8 = 0;
    let mut encoded_length: Vec<u8> = Vec::new();

    while shifted_length > 0 {
        octets_count += 1;
        encoded_length.push(shifted_length as u8);
        shifted_length >>= 8;
    }

    encoded_length.push(octets_count | 0b10000000);

    encoded_length.reverse();

    return encoded_length;
}

/// To parse the object value length from DER, should not be overwritten
pub fn parse_length(raw: &[u8]) -> Result<(&[u8], usize)> {
    let (mut raw, len_byte) =
        be_u8(raw).map_err(|_: nom::Err<(&[u8], nom::error::ErrorKind)>| {
            Error::LengthEmpty
        })?;

    let is_short_form = (len_byte & 0x80) == 0;
    let length = (len_byte & 0x7F) as usize;
    if is_short_form {
        return Ok((raw, length));
    }

    let length_of_length = length;
    let mut length = 0;

    for _ in 1..(length_of_length + 1) {
        length <<= 8;
        let (raw_tmp, len_byte) = be_u8(raw).map_err(
            |_: nom::Err<(&[u8], nom::error::ErrorKind)>| {
                Error::NotEnoughLengthOctects
            },
        )?;
        length += len_byte as usize;
        raw = raw_tmp;
    }
    return Ok((raw, length));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_length() {
        assert_eq!(vec![0x0], build_length(0));
        assert_eq!(vec![0x1], build_length(1));
        assert_eq!(vec![0x7F], build_length(127));
        assert_eq!(vec![0x81, 0x80], build_length(128));
        assert_eq!(vec![0x81, 0xFF], build_length(255));
        assert_eq!(vec![0x82, 0x01, 0x00], build_length(256));
        assert_eq!(vec![0x82, 0xFF, 0xFF], build_length(65535));
        assert_eq!(vec![0x83, 0x01, 0x00, 0x00], build_length(65536));

        assert_eq!(
            vec![0x84, 0x10, 0xf3, 0x91, 0xbd],
            build_length(0x10f391bd)
        );
        assert_eq!(vec![0x84, 0x0f, 0xc4, 0x69, 0x89], build_length(0xfc46989));
        assert_eq!(
            vec![0x84, 0x31, 0xb2, 0x50, 0x42],
            build_length(0x31b25042)
        );
        assert_eq!(
            vec![0x84, 0x13, 0x93, 0xaa, 0x93],
            build_length(0x1393aa93)
        );
        assert_eq!(vec![0x84, 0x05, 0x71, 0x6f, 0xa9], build_length(0x5716fa9));
    }

    #[test]
    fn test_parse_length() {
        let x: &[u8] = &[];
        assert_eq!((x, 0), parse_length(&[0x0]).unwrap());
        assert_eq!((x, 1), parse_length(&[0x1]).unwrap());
        assert_eq!((x, 127), parse_length(&[0x7F]).unwrap());
        assert_eq!((x, 128), parse_length(&[0x81, 0x80]).unwrap());
        assert_eq!((x, 255), parse_length(&[0x81, 0xFF]).unwrap());
        assert_eq!((x, 256), parse_length(&[0x82, 0x01, 0x00]).unwrap());
        assert_eq!((x, 65535), parse_length(&[0x82, 0xFF, 0xFF]).unwrap());
        assert_eq!(
            (x, 65536),
            parse_length(&[0x83, 0x01, 0x00, 0x00]).unwrap()
        );

        assert_eq!(
            (x, 0x10f391bd),
            parse_length(&[0x84, 0x10, 0xf3, 0x91, 0xbd]).unwrap()
        );
        assert_eq!(
            (x, 0xfc46989),
            parse_length(&[0x84, 0x0f, 0xc4, 0x69, 0x89]).unwrap()
        );
        assert_eq!(
            (x, 0x31b25042),
            parse_length(&[0x84, 0x31, 0xb2, 0x50, 0x42]).unwrap()
        );
        assert_eq!(
            (x, 0x1393aa93),
            parse_length(&[0x84, 0x13, 0x93, 0xaa, 0x93]).unwrap()
        );
        assert_eq!(
            (x, 0x5716fa9),
            parse_length(&[0x84, 0x05, 0x71, 0x6f, 0xa9]).unwrap()
        );
    }
}
