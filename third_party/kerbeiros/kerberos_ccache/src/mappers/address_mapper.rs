use kerberos_asn1::{padd_netbios_string, HostAddress, HostAddresses};
use kerberos_constants::address_types::NETBIOS;
use std::convert::TryInto;
use crate::{Address, CountedOctetString};
use crate::{ConvertResult, ConvertError};

pub fn host_address_to_address(host_address: HostAddress) -> Address {
    let address = if host_address.addr_type == NETBIOS {
        String::from_utf8_lossy(&host_address.address)
            .trim_end()
            .as_bytes()
            .to_vec()
    } else {
        host_address.address
    };

    return Address::new(
        host_address.addr_type as u16,
        CountedOctetString::new(address),
    );
}

pub fn host_addresses_to_address_vector(
    host_addresses: HostAddresses,
) -> Vec<Address> {
    let mut addresses = Vec::new();
    for host_address in host_addresses.into_iter() {
        addresses.push(host_address_to_address(host_address));
    }
    return addresses;
}

pub fn address_to_host_address(address: Address) -> ConvertResult<HostAddress> {
    let address_type = address.addrtype as i32;
    match address_type {
        NETBIOS => {
            return Ok(HostAddress::new(
                NETBIOS,
                padd_netbios_string(address.addrdata.try_into()?).into_bytes(),
            ));
        }
        _ => {
            return Ok(HostAddress::new(address_type, address.addrdata.data));
        }
    }
}

pub fn address_vector_to_host_addresses(
    mut addresses: Vec<Address>,
) -> ConvertResult<HostAddresses> {
    if addresses.len() == 0 {
        return Err(ConvertError::NoAddress);
    }
    let main_address = addresses.remove(0);

    let mut host_addresses = vec![address_to_host_address(main_address)?];

    while addresses.len() > 0 {
        host_addresses
            .push(address_to_host_address(addresses.remove(0))?);
    }

    return Ok(host_addresses);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_host_address_to_address() {
        let host_address = HostAddress::new(
            NETBIOS,
            padd_netbios_string("KINGDOM.HEARTS".to_string()).into_bytes(),
        );

        let address = Address::new(
            NETBIOS as u16,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
        );

        assert_eq!(
            address,
            host_address_to_address(host_address)
        );
    }

    #[test]
    fn test_host_addresses_to_address_vector() {
        let mut addresses = Vec::new();
        addresses.push(Address::new(
            NETBIOS as u16,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
        ));
        addresses.push(Address::new(
            7,
            CountedOctetString::new("HOLLOWBASTION".as_bytes().to_vec()),
        ));

        let host_addresses = vec![
            HostAddress::new(
                NETBIOS,
                padd_netbios_string("KINGDOM.HEARTS".to_string()).into_bytes(),
            ),
            HostAddress::new(7, "HOLLOWBASTION".as_bytes().to_vec()),
        ];

        assert_eq!(
            addresses,
            host_addresses_to_address_vector(host_addresses)
        );
    }

    #[test]
    fn test_address_to_host_address() {
        let host_address = HostAddress::new(
            NETBIOS,
            padd_netbios_string("KINGDOM.HEARTS".to_string()).into_bytes(),
        );

        let address = Address::new(
            NETBIOS as u16,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
        );

        assert_eq!(
            host_address,
            address_to_host_address(address).unwrap()
        );
    }

    #[test]
    fn test_address_to_host_address_raw() {
        let host_address = HostAddress::new(1, vec![1, 2, 3]);

        let address = Address::new(1, CountedOctetString::new(vec![1, 2, 3]));

        assert_eq!(
            host_address,
            address_to_host_address(address).unwrap()
        );
    }

    #[test]
    fn test_address_vector_to_host_addresses() {
        let mut addresses = Vec::new();
        addresses.push(Address::new(
            NETBIOS as u16,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
        ));
        addresses.push(Address::new(
            7,
            CountedOctetString::new("HOLLOWBASTION".as_bytes().to_vec()),
        ));

        let host_addresses = vec![
            HostAddress::new(
                NETBIOS,
                padd_netbios_string("KINGDOM.HEARTS".to_string()).into_bytes(),
            ),
            HostAddress::new(7, "HOLLOWBASTION".as_bytes().to_vec()),
        ];

        assert_eq!(
            host_addresses,
            address_vector_to_host_addresses(addresses).unwrap()
        );
    }

    #[test]
    #[should_panic(expected = "NoAddress")]
    fn test_address_vector_to_host_addresses_panic() {
        let addresses = Vec::new();
        address_vector_to_host_addresses(addresses).unwrap();
    }
}
