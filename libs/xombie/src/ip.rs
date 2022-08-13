/// Convert a string representaion of an IPV4 address to an array of four bytes
///
/// ```
/// # use xombie::ip::ipv4_str_as_bytes;
/// let addr = ipv4_str_as_bytes("10.24.73.99");
/// assert_eq!(Some([10, 24, 73, 99]), addr);
/// ```
pub fn ipv4_str_as_bytes(s: &str) -> Option<[u8;4]> {
    let captures = regex::Regex::new("^(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)$")
        .ok()?
        .captures(s)?;

    Some([
        captures[1].parse().ok()?,
        captures[2].parse().ok()?,
        captures[3].parse().ok()?,
        captures[4].parse().ok()?,
    ])
}

#[cfg(test)]
mod tests {
    use super::ipv4_str_as_bytes;

    #[test]
    fn ipv4_str_as_bytes_good() {
        assert_eq!(Some([  0,   0,   0,   0]), ipv4_str_as_bytes("0.0.0.0"));
        assert_eq!(Some([ 10,  24,  73,  99]), ipv4_str_as_bytes("10.24.73.99"));
        assert_eq!(Some([192, 168,   0,   1]), ipv4_str_as_bytes("192.168.0.1"));
        assert_eq!(Some([255, 255, 255, 255]), ipv4_str_as_bytes("255.255.255.255"));
    }

    #[test]
    fn ipv4_str_as_bytes_fails_with_wrong_number_of_arguments() {
        assert_eq!(None, ipv4_str_as_bytes("0.0.0.0.0"));
        assert_eq!(None, ipv4_str_as_bytes("0.0.0"));
    }

    #[test]
    fn ipv4_str_as_bytes_fails_with_arguments_out_of_bounds() {
        assert_eq!(None, ipv4_str_as_bytes("256.0.0.0"));
        assert_eq!(None, ipv4_str_as_bytes("-1.0.0.0"));
    }
}