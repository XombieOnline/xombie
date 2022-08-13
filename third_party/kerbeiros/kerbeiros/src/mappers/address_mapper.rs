use crate::{Error, Result};
use kerberos_asn1::{padd_netbios_string, HostAddress, HostAddresses};
use kerberos_ccache::{Address, CountedOctetString};
use kerberos_constants::address_types::NETBIOS;
use std::convert::TryInto;

pub struct AddressMapper {}

impl AddressMapper {
    pub fn host_address_to_address(host_address: &HostAddress) -> Address {

        let address = if host_address.addr_type == NETBIOS {
            String::from_utf8_lossy(&host_address.address).trim_end().as_bytes().to_vec()
        } else {
            host_address.address.clone()
        };
        
        return Address::new(
            host_address.addr_type as u16,
            CountedOctetString::new(address),
        );
    }

    pub fn host_addresses_to_address_vector(
        host_addresses: &HostAddresses,
    ) -> Vec<Address> {
        let mut addresses = Vec::new();
        for host_address in host_addresses.iter() {
            addresses.push(Self::host_address_to_address(host_address));
        }
        return addresses;
    }

    pub fn address_to_host_address(address: Address) -> Result<HostAddress> {
        let address_type = address.addrtype as i32;
        match address_type {
            NETBIOS => {
                return Ok(HostAddress::new(
                    NETBIOS,
                    padd_netbios_string(address.addrdata.try_into()?)
                        .into_bytes(),
                ));
            }
            _ => {
                return Ok(HostAddress::new(
                    address_type,
                    address.addrdata.data,
                ));
            }
        }
    }

    pub fn address_vector_to_host_addresses(
        mut addresses: Vec<Address>,
    ) -> Result<HostAddresses> {
        if addresses.len() == 0 {
            return Err(Error::NoAddress)?;
        }
        let main_address = addresses.remove(0);

        let mut host_addresses =
            vec![Self::address_to_host_address(main_address)?];

        while addresses.len() > 0 {
            host_addresses
                .push(Self::address_to_host_address(addresses.remove(0))?);
        }

        return Ok(host_addresses);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn host_address_to_address() {
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
            AddressMapper::host_address_to_address(&host_address)
        );
    }

    #[test]
    fn host_addresses_to_address_vector() {
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
            HostAddress::new(
                7,
                "HOLLOWBASTION".as_bytes().to_vec(),
            ),
        ];

        assert_eq!(
            addresses,
            AddressMapper::host_addresses_to_address_vector(&host_addresses)
        );
    }

    #[test]
    fn address_to_host_address() {
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
            AddressMapper::address_to_host_address(address).unwrap()
        );
    }

    #[test]
    fn address_to_host_address_raw() {
        let host_address = HostAddress::new(1, vec![1, 2, 3]);

        let address = Address::new(1, CountedOctetString::new(vec![1, 2, 3]));

        assert_eq!(
            host_address,
            AddressMapper::address_to_host_address(address).unwrap()
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
            HostAddress::new(
                7,
                "HOLLOWBASTION".as_bytes().to_vec(),
            ),
        ];

        assert_eq!(
            host_addresses,
            AddressMapper::address_vector_to_host_addresses(addresses).unwrap()
        );
    }

    #[test]
    #[should_panic(expected = "NoAddress")]
    fn test_address_vector_to_host_addresses_panic() {
        let addresses = Vec::new();
        AddressMapper::address_vector_to_host_addresses(addresses).unwrap();
    }
}
