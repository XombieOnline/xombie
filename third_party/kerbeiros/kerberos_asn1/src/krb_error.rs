use crate::{
    Int32, KerberosString, KerberosTime, Microseconds, PrincipalName, Realm,
};
use red_asn1::{Asn1Object, OctetString};
use red_asn1_derive::Sequence;

/// (*KRB-ERROR*) Message used to indicate an error.
/// Defined in RFC4120, section 5.9.1.
/// ```asn1
/// KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
///        pvno            [0] INTEGER (5),
///        msg-type        [1] INTEGER (30),
///        ctime           [2] KerberosTime OPTIONAL,
///        cusec           [3] Microseconds OPTIONAL,
///        stime           [4] KerberosTime,
///        susec           [5] Microseconds,
///        error-code      [6] Int32,
///        crealm          [7] Realm OPTIONAL,
///        cname           [8] PrincipalName OPTIONAL,
///        realm           [9] Realm -- service realm --,
///        sname           [10] PrincipalName -- service name --,
///        e-text          [11] KerberosString OPTIONAL,
///        e-data          [12] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
#[seq(application_tag = 30)]
pub struct KrbError {
    #[seq_field(context_tag = 0)]
    pub pvno: Int32,
    #[seq_field(context_tag = 1)]
    pub msg_type: Int32,
    #[seq_field(context_tag = 2)]
    pub ctime: Option<KerberosTime>,
    #[seq_field(context_tag = 3)]
    pub cusec: Option<Microseconds>,
    #[seq_field(context_tag = 4)]
    pub stime: KerberosTime,
    #[seq_field(context_tag = 5)]
    pub susec: Microseconds,
    #[seq_field(context_tag = 6)]
    pub error_code: Int32,
    #[seq_field(context_tag = 7)]
    pub crealm: Option<Realm>,
    #[seq_field(context_tag = 8)]
    pub cname: Option<PrincipalName>,
    #[seq_field(context_tag = 9)]
    pub realm: Realm,
    #[seq_field(context_tag = 10)]
    pub sname: PrincipalName,
    #[seq_field(context_tag = 11)]
    pub e_text: Option<KerberosString>,
    #[seq_field(context_tag = 12)]
    pub e_data: Option<OctetString>,
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::error_codes::*;
    use kerberos_constants::etypes::*;
    use kerberos_constants::pa_data_types::*;
    use kerberos_constants::principal_names::*;
    use chrono::prelude::*;
    use crate::{EtypeInfo2Entry, PaData};

    #[test]
    fn test_parse_krb_error() {
        let info2 = vec![
            EtypeInfo2Entry {
                etype: AES256_CTS_HMAC_SHA1_96,
                salt: Some(KerberosString::from("KINGDOM.HEARTSmickey")),
                s2kparams: None
            },
            EtypeInfo2Entry {
                etype: RC4_HMAC,
                salt: None,
                s2kparams: None
            },
            EtypeInfo2Entry {
                etype: DES_CBC_MD5,
                salt: Some(KerberosString::from("KINGDOM.HEARTSmickey")),
                s2kparams: None
            },
            
        ];

        let pa_datas = vec![
            PaData{
                padata_type: PA_ETYPE_INFO2,
                padata_value: info2.build()
            },
            PaData{
                padata_type: PA_ENC_TIMESTAMP,
                padata_value: vec![]
            },
            PaData{
                padata_type: PA_PK_AS_REQ,
                padata_value: vec![]
            },
            PaData{
                padata_type: PA_PK_AS_REP_OLD,
                padata_value: vec![]
            },
        ];

        let sname = PrincipalName {
            name_type: NT_SRV_INST,
            name_string: vec![
                KerberosString::from("krbtgt"),
                KerberosString::from("KINGDOM.HEARTS"),
            ],
        };
        
        let krb_error = KrbError {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            stime: KerberosTime::from(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31)),
            susec: 341039,
            error_code: KDC_ERR_PREAUTH_REQUIRED,
            crealm: None,
            cname: None,
            realm: Realm::from("KINGDOM.HEARTS"),
            sname,
            e_text: None,
            e_data: Some(pa_datas.build())
        };

        assert_eq!(krb_error, KrbError::parse(&[
                0x7e, 0x81, 0xdc, 0x30, 0x81, 0xd9, 0xa0, 0x03, 0x02, 0x01,
                0x05, 0xa1, 0x03, 0x02, 0x01, 0x1e, 0xa4, 0x11, 0x18, 0x0f,
                0x32, 0x30, 0x31, 0x39, 0x30, 0x34, 0x31, 0x38, 0x30, 0x36,
                0x30, 0x30, 0x33, 0x31, 0x5a, 0xa5, 0x05, 0x02, 0x03, 0x05,
                0x34, 0x2f, 0xa6, 0x03, 0x02, 0x01, 0x19, 0xa9, 0x10, 0x1b,
                0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48,
                0x45, 0x41, 0x52, 0x54, 0x53, 0xaa, 0x23, 0x30, 0x21, 0xa0,
                0x03, 0x02, 0x01, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06,
                0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49,
                0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52,
                0x54, 0x53, 0xac, 0x77, 0x04, 0x75, 0x30, 0x73, 0x30, 0x50,
                0xa1, 0x03, 0x02, 0x01, 0x13, 0xa2, 0x49, 0x04, 0x47, 0x30,
                0x45, 0x30, 0x1d, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x16,
                0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e,
                0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b,
                0x65, 0x79, 0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x17, 0x30,
                0x1d, 0xa0, 0x03, 0x02, 0x01, 0x03, 0xa1, 0x16, 0x1b, 0x14,
                0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45,
                0x41, 0x52, 0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79,
                0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x02, 0xa2, 0x02, 0x04,
                0x00, 0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x10, 0xa2, 0x02,
                0x04, 0x00, 0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x0f, 0xa2,
                0x02, 0x04, 0x00,
            ]).unwrap().1);
    }

}
