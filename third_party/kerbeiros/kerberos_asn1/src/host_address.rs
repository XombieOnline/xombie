use super::Int32;
use red_asn1::{Asn1Object, OctetString, SequenceOf};
use red_asn1_derive::Sequence;

static NETBIOS_PADDING_CHAR: char = 32 as char;

/// (*HostAddress*) Different types of addresses.
/// ```asn1
/// HostAddress ::= SEQUENCE {
///         addr-type   [0] Int32,
///         address     [1] OCTET STRING
/// }
/// ```

#[derive(Sequence, Default, Debug, PartialEq, Clone)]
pub struct HostAddress {
    #[seq_field(context_tag = 0)]
    pub addr_type: Int32,
    #[seq_field(context_tag = 1)]
    pub address: OctetString,
}

impl HostAddress {
    pub fn new(addr_type: Int32, address: OctetString) -> Self {
        return Self { addr_type, address };
    }
}

/// Helper to add the correct padding to a NetBIOS *Host-Address*
pub fn padd_netbios_string(string: String) -> String {
    let mut padded_string = string;
    let mut padded_len = padded_string.len() % 16;

    if padded_len > 0 {
        padded_len = 16 - padded_len;
        for _ in 0..padded_len {
            padded_string.push(NETBIOS_PADDING_CHAR);
        }
    }

    return padded_string;
}

/// (*HostAddresses*) Array of [HostAddress](./enum.HostAddress.html)
/// ```asn1
/// HostAddresses ::= SEQUENCE OF HostAddress
/// ```
pub type HostAddresses = SequenceOf<HostAddress>;

#[cfg(test)]
mod tests {
    use super::*;
    use kerberos_constants::address_types;

    #[test]
    fn test_encode_netbios_host_address() {
        let netbios_address = HostAddress::new(
            address_types::NETBIOS,
            padd_netbios_string("HOLLOWBASTION".to_string()).into_bytes(),
        );
        assert_eq!(
            vec![
                0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 0xa1, 0x12, 0x04,
                0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x42, 0x41, 0x53,
                0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20
            ],
            netbios_address.build()
        );
    }

    #[test]
    fn test_netbios_padding() {
        assert_eq!(
            Vec::<u8>::new(),
            padd_netbios_string("".to_string()).into_bytes()
        );

        assert_eq!(
            vec![
                0x31, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20
            ],
            padd_netbios_string("1".to_string()).into_bytes()
        );

        assert_eq!(
            vec![
                0x31, 0x32, 0x33, 0x34, 0x35, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20
            ],
            padd_netbios_string("12345".to_string()).into_bytes()
        );

        assert_eq!(
            vec![
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36
            ],
            padd_netbios_string("1234567890123456".to_string()).into_bytes()
        );

        assert_eq!(
            vec![
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x20, 0x20, 0x20,
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x20, 0x20
            ],
            padd_netbios_string("12345678901234567".to_string()).into_bytes()
        );
    }

    #[test]
    fn test_decode_netbios_host_address() {
        let netbios_address = HostAddress::new(
            address_types::NETBIOS,
            padd_netbios_string("HOLLOWBASTION".to_string()).into_bytes(),
        );
        assert_eq!(
            netbios_address,
            HostAddress::parse(&[
                0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 0xa1, 0x12, 0x04,
                0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x42, 0x41, 0x53,
                0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20,
            ])
            .unwrap()
            .1
        );
    }

    #[test]
    fn test_encode_netbios_host_addresses() {
        let netbios_address = HostAddress::new(
            address_types::NETBIOS,
            padd_netbios_string("HOLLOWBASTION".to_string()).into_bytes(),
        );
        let addresses = vec![netbios_address];
        assert_eq!(
            vec![
                0x30, 0x1b, 0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 0xa1,
                0x12, 0x04, 0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x42,
                0x41, 0x53, 0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20
            ],
            addresses.build()
        );
    }

    #[test]
    fn test_decode_netbios_host_addresses() {
        let netbios_address = HostAddress::new(
            address_types::NETBIOS,
            padd_netbios_string("HOLLOWBASTION".to_string()).into_bytes(),
        );
        let addresses = vec![netbios_address];
        assert_eq!(
            addresses,
            HostAddresses::parse(&[
                0x30, 0x1b, 0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 0xa1,
                0x12, 0x04, 0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x42,
                0x41, 0x53, 0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20,
            ])
            .unwrap()
            .1
        );
    }
}
