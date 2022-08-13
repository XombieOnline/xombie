use crate::error as asn1err;

pub fn parse_integer_value(
    raw: &[u8],
    max_length: usize,
) -> asn1err::Result<i128> {
    if raw.len() == 0 {
        return Err(asn1err::Error::IncorrectValue(format!(
            "No octets for i{}",
            max_length * 8
        )))?;
    }

    if raw.len() > max_length {
        return Err(asn1err::Error::IncorrectValue(format!(
            "Too many octets for i{}: {} octets",
            max_length * 8,
            raw.len()
        )))?;
    }

    let signed_bit = (raw[0] & 0x80) >> 7;
    let mut value = (signed_bit as i128) * -1;

    for byte in raw.iter() {
        value <<= 8;
        value += (*byte as i128) & 0xFF;
    }

    return Ok(value);
}

pub fn parse_uinteger_value(
    raw: &[u8],
    max_length: usize,
) -> asn1err::Result<i128> {
    if raw.len() == 0 {
        return Err(asn1err::Error::IncorrectValue(format!(
            "No octets for u{}",
            max_length * 8
        )))?;
    }

    if raw.len() == max_length + 1 {
        if raw[0] != 0 {
            return Err(asn1err::Error::IncorrectValue(format!(
                "Non zero extra octet for u{}",
                max_length * 8
            )))?;
        }
    } else if raw.len() > max_length {
        return Err(asn1err::Error::IncorrectValue(format!(
            "Too many octets for u{}: {} octets",
            max_length * 8,
            raw.len()
        )))?;
    }

    let signed_bit = (raw[0] & 0x80) >> 7;
    let mut value = (signed_bit as i128) * -1;

    for byte in raw.iter() {
        value <<= 8;
        value += (*byte as i128) & 0xFF;
    }

    return Ok(value);
}

pub fn build_integer_value(int: i128) -> Vec<u8> {
    let mut shifted_value = int;
    let length = calculate_integer_length(int);

    let mut encoded_value: Vec<u8> = Vec::new();

    for _ in 0..length {
        encoded_value.push((shifted_value & 0xFF) as u8);
        shifted_value >>= 8;
    }

    encoded_value.reverse();

    return encoded_value;
}

fn calculate_integer_length(int: i128) -> usize {
    if int >= 0 {
        return calculate_positive_integer_length(int);
    }
    return calculate_negative_integer_length(int);
}

fn calculate_negative_integer_length(int: i128) -> usize {
    let mut bytes_count = 1;
    let mut shifted_integer = int;

    while shifted_integer < -128 {
        bytes_count += 1;
        shifted_integer >>= 8;
    }

    return bytes_count;
}

fn calculate_positive_integer_length(int: i128) -> usize {
    let mut bytes_count = 1;
    let mut shifted_integer = int;

    while shifted_integer > 127 {
        bytes_count += 1;
        shifted_integer >>= 8;
    }

    return bytes_count;
}
