use crate::{
    EncryptionKey, HostAddresses, KerberosTime, LastReq, PrincipalName, Realm,
    TicketFlags, UInt32, PaData, EncKdcRepPart, EncTgsRepPart
};
use red_asn1::{SequenceOf, Asn1Object};
use red_asn1_derive::Sequence;

/// (*EncAsRepPart*) Holds the data that is encrypted
/// in [AsRep](./struct.AsRep.html)
///
/// ```asn1
/// EncASRepPart    ::= [APPLICATION 25] EncKDCRepPart
/// EncKDCRepPart   ::= SEQUENCE {
///        key                [0] EncryptionKey,
///        last-req           [1] LastReq,
///        nonce              [2] UInt32,
///        key-expiration     [3] KerberosTime OPTIONAL,
///        flags              [4] TicketFlags,
///        authtime           [5] KerberosTime,
///        starttime          [6] KerberosTime OPTIONAL,
///        endtime            [7] KerberosTime,
///        renew-till         [8] KerberosTime OPTIONAL,
///        srealm             [9] Realm,
///        sname             [10] PrincipalName,
///        caddr             [11] HostAddresses OPTIONAL
///        encrypted-pa-data [12] SEQUENCE OF PA-DATA OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Debug, PartialEq, Clone)]
#[seq(application_tag = 25)]
pub struct EncAsRepPart {
    #[seq_field(context_tag = 0)]
    pub key: EncryptionKey,
    #[seq_field(context_tag = 1)]
    pub last_req: LastReq,
    #[seq_field(context_tag = 2)]
    pub nonce: UInt32,
    #[seq_field(context_tag = 3)]
    pub key_expiration: Option<KerberosTime>,
    #[seq_field(context_tag = 4)]
    pub flags: TicketFlags,
    #[seq_field(context_tag = 5)]
    pub authtime: KerberosTime,
    #[seq_field(context_tag = 6)]
    pub starttime: Option<KerberosTime>,
    #[seq_field(context_tag = 7)]
    pub endtime: KerberosTime,
    #[seq_field(context_tag = 8)]
    pub renew_till: Option<KerberosTime>,
    #[seq_field(context_tag = 9)]
    pub srealm: Realm,
    #[seq_field(context_tag = 10)]
    pub sname: PrincipalName,
    #[seq_field(context_tag = 11)]
    pub caddr: Option<HostAddresses>,
    #[seq_field(context_tag = 12)]
    pub encrypted_pa_data: Option<SequenceOf<PaData>>,
}

impl From<EncKdcRepPart> for EncAsRepPart {
    fn from(rep_part: EncKdcRepPart) -> Self {
        Self {
            key: rep_part.key,
            last_req: rep_part.last_req,
            nonce: rep_part.nonce,
            key_expiration: rep_part.key_expiration,
            flags: rep_part.flags,
            authtime: rep_part.authtime,
            starttime: rep_part.starttime,
            endtime: rep_part.endtime,
            renew_till: rep_part.renew_till,
            srealm: rep_part.srealm,
            sname: rep_part.sname,
            caddr: rep_part.caddr,
            encrypted_pa_data: rep_part.encrypted_pa_data,
        }
    }
}

impl From<EncTgsRepPart> for EncAsRepPart {
    fn from(rep_part: EncTgsRepPart) -> Self {
        Self {
            key: rep_part.key,
            last_req: rep_part.last_req,
            nonce: rep_part.nonce,
            key_expiration: rep_part.key_expiration,
            flags: rep_part.flags,
            authtime: rep_part.authtime,
            starttime: rep_part.starttime,
            endtime: rep_part.endtime,
            renew_till: rep_part.renew_till,
            srealm: rep_part.srealm,
            sname: rep_part.sname,
            caddr: rep_part.caddr,
            encrypted_pa_data: rep_part.encrypted_pa_data,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::address_types::*;
    use kerberos_constants::etypes::*;
    use kerberos_constants::principal_names::*;
    use kerberos_constants::ticket_flags::*;
    use kerberos_constants::pa_data_types::*;
    use crate::{
        padd_netbios_string, HostAddress, KerberosString, LastReqEntry,
    };
    use chrono::prelude::*;

    #[test]
    fn parse_enc_as_rep_part() {
        let raw: Vec<u8> = vec![
            0x79, 0x82, 0x01, 0x29, 0x30, 0x82, 0x01, 0x25, 0xa0, 0x2b, 0x30,
            0x29, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x22, 0x04, 0x20, 0x63,
            0x7b, 0x4d, 0x21, 0x38, 0x22, 0x5a, 0x3a, 0x0a, 0xd7, 0x93, 0x5a,
            0xf3, 0x31, 0x22, 0x68, 0x50, 0xeb, 0x53, 0x1d, 0x2d, 0x40, 0xf2,
            0x19, 0x19, 0xd0, 0x08, 0x41, 0x91, 0x72, 0x17, 0xff, 0xa1, 0x1c,
            0x30, 0x1a, 0x30, 0x18, 0xa0, 0x03, 0x02, 0x01, 0x00, 0xa1, 0x11,
            0x18, 0x0f, 0x32, 0x30, 0x31, 0x39, 0x30, 0x34, 0x31, 0x38, 0x30,
            0x36, 0x30, 0x30, 0x33, 0x31, 0x5a, 0xa2, 0x06, 0x02, 0x04, 0x06,
            0x3c, 0xc3, 0x54, 0xa3, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x37,
            0x30, 0x39, 0x31, 0x34, 0x30, 0x32, 0x34, 0x38, 0x30, 0x35, 0x5a,
            0xa4, 0x07, 0x03, 0x05, 0x00, 0x40, 0xe0, 0x00, 0x00, 0xa5, 0x11,
            0x18, 0x0f, 0x32, 0x30, 0x31, 0x39, 0x30, 0x34, 0x31, 0x38, 0x30,
            0x36, 0x30, 0x30, 0x33, 0x31, 0x5a, 0xa6, 0x11, 0x18, 0x0f, 0x32,
            0x30, 0x31, 0x39, 0x30, 0x34, 0x31, 0x38, 0x30, 0x36, 0x30, 0x30,
            0x33, 0x31, 0x5a, 0xa7, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39,
            0x30, 0x34, 0x31, 0x38, 0x31, 0x36, 0x30, 0x30, 0x33, 0x31, 0x5a,
            0xa8, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39, 0x30, 0x34, 0x32,
            0x35, 0x30, 0x36, 0x30, 0x30, 0x33, 0x31, 0x5a, 0xa9, 0x10, 0x1b,
            0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45,
            0x41, 0x52, 0x54, 0x53, 0xaa, 0x23, 0x30, 0x21, 0xa0, 0x03, 0x02,
            0x01, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72, 0x62,
            0x74, 0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f,
            0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xab, 0x1d, 0x30,
            0x1b, 0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 0xa1, 0x12, 0x04,
            0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x42, 0x41, 0x53, 0x54,
            0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20, 0xac, 0x12, 0x30, 0x10, 0x30,
            0x0e, 0xa1, 0x04, 0x02, 0x02, 0x00, 0xa5, 0xa2, 0x06, 0x04, 0x04,
            0x1f, 0x00, 0x00, 0x00,
        ];

        let encryption_key = EncryptionKey {
            keytype: AES256_CTS_HMAC_SHA1_96,
            keyvalue: vec![
                0x63, 0x7b, 0x4d, 0x21, 0x38, 0x22, 0x5a, 0x3a, 0x0a, 0xd7,
                0x93, 0x5a, 0xf3, 0x31, 0x22, 0x68, 0x50, 0xeb, 0x53, 0x1d,
                0x2d, 0x40, 0xf2, 0x19, 0x19, 0xd0, 0x08, 0x41, 0x91, 0x72,
                0x17, 0xff,
            ],
        };

        let last_req = vec![LastReqEntry {
            lr_type: 0,
            lr_value: KerberosTime::from(
                Utc.ymd(2019, 4, 18).and_hms(06, 00, 31),
            ),
        }];

        let ticket_flags =
            TicketFlags::from(INITIAL | FORWARDABLE | PRE_AUTHENT | RENEWABLE);

        let sname = PrincipalName {
            name_type: NT_SRV_INST,
            name_string: vec![
                KerberosString::from("krbtgt"),
                KerberosString::from("KINGDOM.HEARTS"),
            ],
        };

        let netbios_address = HostAddress::new(
            NETBIOS,
            padd_netbios_string("HOLLOWBASTION".to_string()).into_bytes(),
        );

        let encrypted_pa_datas = vec![
            PaData {
                padata_type: PA_SUPPORTED_ENCTYPES,
                padata_value: vec![0x1f, 0x0, 0x0, 0x0],
            }
        ];
        
        let enc_as_rep_part = EncAsRepPart {
            key: encryption_key,
            last_req,
            nonce: 104645460,
            key_expiration: Some(KerberosTime::from(
                Utc.ymd(2037, 9, 14).and_hms(02, 48, 05),
            )),
            flags: ticket_flags,
            authtime: KerberosTime::from(
                Utc.ymd(2019, 4, 18).and_hms(06, 00, 31),
            ),
            starttime: Some(KerberosTime::from(
                Utc.ymd(2019, 4, 18).and_hms(06, 00, 31),
            )),
            endtime: KerberosTime::from(
                Utc.ymd(2019, 4, 18).and_hms(16, 00, 31),
            ),
            renew_till: Some(KerberosTime::from(
                Utc.ymd(2019, 4, 25).and_hms(06, 00, 31),
            )),
            srealm: Realm::from("KINGDOM.HEARTS"),
            sname,
            caddr: Some(vec![netbios_address]),
            encrypted_pa_data: Some(encrypted_pa_datas),
        };

        assert_eq!(
            enc_as_rep_part,
            EncAsRepPart::parse(&raw).unwrap().1
        );
    }
}
