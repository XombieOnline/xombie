use red_asn1::{Asn1Object, SequenceOf};
use red_asn1_derive::Sequence;

use crate::{
    EncryptedData, HostAddresses, Int32, KdcOptions, KerberosTime,
    PrincipalName, Realm, Ticket, UInt32,
};

/// (*KDC-REQ-BODY*) Holds the most part of data of requests.
/// ```asn1
/// KDC-REQ-BODY    ::= SEQUENCE {
///        kdc-options             [0] KDCOptions,
///        cname                   [1] PrincipalName OPTIONAL
///                                    -- Used only in AS-REQ --,
///        realm                   [2] Realm
///                                    -- Server's realm
///                                    -- Also client's in AS-REQ --,
///        sname                   [3] PrincipalName OPTIONAL,
///        from                    [4] KerberosTime OPTIONAL,
///        till                    [5] KerberosTime,
///        rtime                   [6] KerberosTime OPTIONAL,
///        nonce                   [7] UInt32,
///        etype                   [8] SEQUENCE OF Int32 -- EncryptionType
///                                    -- in preference order --,
///        addresses               [9] HostAddresses OPTIONAL,
///        enc-authorization-data  [10] EncryptedData OPTIONAL
///                                    -- AuthorizationData --,
///        additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
///                                        -- NOTE: not empty
/// }
/// ```

#[derive(Sequence, Default, Debug, PartialEq, Clone)]
pub struct KdcReqBody {
    #[seq_field(context_tag = 0)]
    pub kdc_options: KdcOptions,
    #[seq_field(context_tag = 1)]
    pub cname: Option<PrincipalName>,
    #[seq_field(context_tag = 2)]
    pub realm: Realm,
    #[seq_field(context_tag = 3)]
    pub sname: Option<PrincipalName>,
    #[seq_field(context_tag = 4)]
    pub from: Option<KerberosTime>,
    #[seq_field(context_tag = 5)]
    pub till: KerberosTime,
    #[seq_field(context_tag = 6)]
    pub rtime: Option<KerberosTime>,
    #[seq_field(context_tag = 7)]
    pub nonce: UInt32,
    #[seq_field(context_tag = 8)]
    pub etypes: SequenceOf<Int32>,
    #[seq_field(context_tag = 9)]
    pub addresses: Option<HostAddresses>,
    #[seq_field(context_tag = 10)]
    pub enc_authorization_data: Option<EncryptedData>,
    #[seq_field(context_tag = 11)]
    pub additional_tickets: Option<SequenceOf<Ticket>>,
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::address_types::NETBIOS;
    use kerberos_constants::etypes::*;
    use kerberos_constants::kdc_options::*;
    use kerberos_constants::principal_names::*;
    use crate::{padd_netbios_string, HostAddress};
    use chrono::prelude::*;

    #[test]
    fn test_encode_kdc_req_body() {
        let mut sname = PrincipalName::new(NT_SRV_INST, "krbtgt".to_string());
        sname.push("KINGDOM.HEARTS".to_string());

        let kdc_req_body = KdcReqBody {
            kdc_options: KdcOptions::from(
                FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK,
            ),
            cname: Some(PrincipalName::new(NT_PRINCIPAL, "mickey".to_string())),
            realm: "KINGDOM.HEARTS".to_string(),
            sname: Some(sname),
            from: None,
            till: KerberosTime::from(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5)),
            rtime: Some(KerberosTime::from(
                Utc.ymd(2037, 9, 13).and_hms(02, 48, 5),
            )),
            nonce: 101225910,
            etypes: vec![
                AES256_CTS_HMAC_SHA1_96,
                AES128_CTS_HMAC_SHA1_96,
                RC4_HMAC,
                RC4_HMAC_EXP,
                RC4_HMAC_OLD_EXP,
                DES_CBC_MD5,
            ],
            addresses: Some(vec![HostAddress::new(
                NETBIOS,
                padd_netbios_string("HOLLOWBASTION".to_string()).into_bytes(),
            )]),
            enc_authorization_data: None,
            additional_tickets: None,
        };

        assert_eq!(
            vec![
                0x30, 0x81, 0xb9, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81,
                0x00, 0x10, 0xa1, 0x13, 0x30, 0x11, 0xa0, 0x03, 0x02, 0x01,
                0x01, 0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d, 0x69, 0x63,
                0x6b, 0x65, 0x79, 0xa2, 0x10, 0x1b, 0x0e, 0x4b, 0x49, 0x4e,
                0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54,
                0x53, 0xa3, 0x23, 0x30, 0x21, 0xa0, 0x03, 0x02, 0x01, 0x02,
                0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74,
                0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f,
                0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa5, 0x11,
                0x18, 0x0f, 0x32, 0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33,
                0x30, 0x32, 0x34, 0x38, 0x30, 0x35, 0x5a, 0xa6, 0x11, 0x18,
                0x0f, 0x32, 0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33, 0x30,
                0x32, 0x34, 0x38, 0x30, 0x35, 0x5a, 0xa7, 0x06, 0x02, 0x04,
                0x06, 0x08, 0x95, 0xb6, 0xa8, 0x15, 0x30, 0x13, 0x02, 0x01,
                0x12, 0x02, 0x01, 0x11, 0x02, 0x01, 0x17, 0x02, 0x01, 0x18,
                0x02, 0x02, 0xff, 0x79, 0x02, 0x01, 0x03, 0xa9, 0x1d, 0x30,
                0x1b, 0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 0xa1, 0x12,
                0x04, 0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x42, 0x41,
                0x53, 0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20
            ],
            kdc_req_body.build()
        );
    }
}
