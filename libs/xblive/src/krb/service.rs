use std::convert::TryInto;

use bytes::BufMut;

use nom::number::streaming::{le_u16, le_u32};

use xbox_sys::account::Xuid;
use xbox_sys::codec::Decode;

use crate::net::InAddr;
use crate::ver::LibraryVersion;

pub const MAX_SERVICES: usize = 12;

pub const INVALID_SERIVCE_ID: u32 = 0;
pub const MAX_SERVICE_ID: u32 = 20;

#[derive(Debug, PartialEq)]
pub enum ServiceRequestFromRawError {
}

#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct ServiceRequest {
    pub struct_version: u16,
    pub struct_size: u16,
    pub library_version: LibraryVersion,
    pub title_id: u32,
    pub title_version: u32,
    pub title_region: u32,
    pub xuid: [Xuid;4],
    pub num_services: u32,
    pub service_id: [u32;MAX_SERVICES],
}

impl ServiceRequest {
    pub fn from_raw(bytes: &[u8]) -> Option<ServiceRequest> {
        let (rem, service_request) = Self::decode(bytes)
            .ok()?;

        if rem.len() == 0 {
            Some(service_request)
        } else {
            None
        }
    }
}

impl Decode for ServiceRequest {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, struct_version) = le_u16(input)?;
        let (input, struct_size) = le_u16(input)?;
        let (input, library_version) = LibraryVersion::decode(input)?;
        let (input, title_id) = le_u32(input)?;
        let (input, title_version) = le_u32(input)?;
        let (input, title_region) = le_u32(input)?;
        let (input, xuid0) = Xuid::decode(input)?;
        let (input, xuid1) = Xuid::decode(input)?;
        let (input, xuid2) = Xuid::decode(input)?;
        let (input, xuid3) = Xuid::decode(input)?;
        let (input, num_services) = le_u32(input)?;
        let (input, service_id0) = le_u32(input)?;
        let (input, service_id1) = le_u32(input)?;
        let (input, service_id2) = le_u32(input)?;
        let (input, service_id3) = le_u32(input)?;
        let (input, service_id4) = le_u32(input)?;
        let (input, service_id5) = le_u32(input)?;
        let (input, service_id6) = le_u32(input)?;
        let (input, service_id7) = le_u32(input)?;
        let (input, service_id8) = le_u32(input)?;
        let (input, service_id9) = le_u32(input)?;
        let (input, service_id10) = le_u32(input)?;
        let (input, service_id11) = le_u32(input)?;

        Ok((input, ServiceRequest {
            struct_version,
            struct_size,
            library_version,
            title_id,
            title_version,
            title_region,
            xuid: [
                xuid0,
                xuid1,
                xuid2,
                xuid3,
            ],
            num_services,
            service_id: [
                service_id0,
                service_id1,
                service_id2,
                service_id3,
                service_id4,
                service_id5,
                service_id6,
                service_id7,
                service_id8,
                service_id9,
                service_id10,
                service_id11,
            ]
        }))
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ServiceResult {
    pub id: u32,
    pub hr: u32,
    pub port: u16,
    pub _rsvd_12: u16,
}

impl ServiceResult {
    pub fn build(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.put_u32_le(self.id);
        buf.put_u32_le(self.hr);
        buf.put_u16_le(self.port);
        buf.put_u16_le(self._rsvd_12);

        buf
    }
}

impl Decode for ServiceResult {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, id) = le_u32(input)?;
        let (input, hr) = le_u32(input)?;
        let (input, port) = le_u16(input)?;
        let (input, _rsvd_12) = le_u16(input)?;

        Ok((input, ServiceResult {
            id,
            hr,
            port,
            _rsvd_12,
        }))
    }
}

pub const NUM_SERVICE_RESULTS_PER_ADDRESS: usize = 12;

#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct ServiceAddress {
    pub hr: u32,
    pub hr_user: [u32;4],
    pub user_flags: [u32;4],
    pub bw_limit: u32,
    pub _rsvd_28: u32,
    pub _rsvd_2c: u32,
    pub _rsvd_30: u32,
    pub _rsvd_34: u32,
    pub _rsvd_38: u32,
    pub _rsvd_3c: u32,
    pub _rsvd_40: u32,
    pub _rsvd_44: u32,
    pub site_ip_address: InAddr,
    pub num_services: u32,
    pub service_result: [ServiceResult;NUM_SERVICE_RESULTS_PER_ADDRESS],
}

impl ServiceAddress {
    pub fn build(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.put_u32_le(self.hr);
        for hr_user in self.hr_user.iter() {
            buf.put_u32_le(*hr_user);
        }
        for user_flags in self.user_flags.iter() {
            buf.put_u32_le(*user_flags);
        }
        buf.put_u32_le(self.bw_limit);
        buf.put_u32_le(self._rsvd_28);
        buf.put_u32_le(self._rsvd_2c);
        buf.put_u32_le(self._rsvd_30);
        buf.put_u32_le(self._rsvd_34);
        buf.put_u32_le(self._rsvd_38);
        buf.put_u32_le(self._rsvd_3c);
        buf.put_u32_le(self._rsvd_40);
        buf.put_u32_le(self._rsvd_44);
        buf.put_slice(&self.site_ip_address.build());
        buf.put_u32_le(self.num_services);
        for service_result in self.service_result.iter() {
            buf.put_slice(&service_result.build());
        }

        buf
    }
}

impl Decode for ServiceAddress {
    fn decode<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, hr) = le_u32(input)?;
        let (input, hr_user_0) = le_u32(input)?;
        let (input, hr_user_1) = le_u32(input)?;
        let (input, hr_user_2) = le_u32(input)?;
        let (input, hr_user_3) = le_u32(input)?;
        let (input, user_flags_0) = le_u32(input)?;
        let (input, user_flags_1) = le_u32(input)?;
        let (input, user_flags_2) = le_u32(input)?;
        let (input, user_flags_3) = le_u32(input)?;
        let (input, bw_limit) = le_u32(input)?;
        let (input, _rsvd_28) = le_u32(input)?;
        let (input, _rsvd_2c) = le_u32(input)?;
        let (input, _rsvd_30) = le_u32(input)?;
        let (input, _rsvd_34) = le_u32(input)?;
        let (input, _rsvd_38) = le_u32(input)?;
        let (input, _rsvd_3c) = le_u32(input)?;
        let (input, _rsvd_40) = le_u32(input)?;
        let (input, _rsvd_44) = le_u32(input)?;
        let (input, site_ip_address) = InAddr::decode(input)?;
        let (input, num_services) = le_u32(input)?;
        let (input, service_result) = nom::multi::count(
            ServiceResult::decode,
            NUM_SERVICE_RESULTS_PER_ADDRESS,
        )(input)?;

        let service_result = service_result.try_into().unwrap();

        Ok((input, ServiceAddress {
            hr,
            hr_user: [hr_user_0, hr_user_1, hr_user_2, hr_user_3],
            user_flags: [user_flags_0, user_flags_1, user_flags_2, user_flags_3],
            bw_limit,
            _rsvd_28,
            _rsvd_2c,
            _rsvd_30,
            _rsvd_34,
            _rsvd_38,
            _rsvd_3c,
            _rsvd_40,
            _rsvd_44,
            num_services,
            site_ip_address,
            service_result,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    #[test]
    fn service_request_from_raw() {
        let raw = hex!["
            01 00
            6c 00
            01 00 00 00 2d 17 01 00
            12 01 ff ff
            00 00 10 00
            07 00 00 80
            00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00
            02 00 00 00
                06 00 00 00
                14 00 00 00
                00 00 00 00
                00 00 00 00
                00 00 00 00
                00 00 00 00
                00 00 00 00
                00 00 00 00
                00 00 00 00
                00 00 00 00
                00 00 00 00
                00 00 00 00"];

        assert_eq!(ServiceRequest::from_raw(&raw), Some(ServiceRequest {
            struct_version: 1,
            struct_size: 0x6c,
            library_version: LibraryVersion {
                major: 1,
                minor: 0,
                build: 0x172d,
                qfe: 1,
            },
            title_id: 0xFFFF0112,
            title_version: 0x00100000,
            title_region: 0x80000007,
            xuid: [
                Xuid::INVALID,
                Xuid::INVALID,
                Xuid::INVALID,
                Xuid::INVALID,
            ],
            num_services: 2,
            service_id: [
                6, 20,  0,  0,
                0,  0,  0,  0,
                0,  0,  0,  0,]
        }));
    }

    #[test]
    fn service_result_build() {
        let service_result = ServiceResult {
            id: 0x98765432,
            hr: 0x87654321,
            port: 0xFEFF,
            _rsvd_12: 0x2638,
        };

        assert_eq!(service_result.build(), hex!["
            32 54 76 98
            21 43 65 87
            ff fe
            38 26"]);
    }

    #[test]
    fn service_address_is_correct_size() {
        let service_address = ServiceAddress {
            hr: 0x971ebb52,
            hr_user: [
                0xf9b7f474,
                0x6d582dec,
                0xea9a31ac,
                0x2dadaaf6,
            ],
            user_flags: [
                0xc3c4b191,
                0x9f32cf9d,
                0x4ba6fe50,
                0x689886d0,
            ],
            bw_limit: 0x1cc7bab4,
            _rsvd_28: 0xbb52177b,
            _rsvd_2c: 0xb669f35d,
            _rsvd_30: 0x49a8e090,
            _rsvd_34: 0x03349413,
            _rsvd_38: 0xa1021f83,
            _rsvd_3c: 0x256acb53,
            _rsvd_40: 0x671a64ba,
            _rsvd_44: 0x35b7cc3f,
            site_ip_address: InAddr([0x05, 0x6c, 0xab, 0xe8]),
            num_services: 0xaad07d79,
            service_result: [ServiceResult {
                id: 0,
                hr: 0,
                port: 0,
                _rsvd_12: 0,
            };MAX_SERVICES],
        };

        assert_eq!(0xE0, service_address.build().len())
    }
}