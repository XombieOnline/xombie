use red_asn1::{SequenceOf, Asn1Object};
use red_asn1_derive::Sequence;
use crate::{Int32, PaData, KdcReqBody, KdcReq};

/// (*AS-REQ*) Message used to request a TGT.
/// ```asn1
/// AS-REQ          ::= [APPLICATION 10] KDC-REQ
///
/// KDC-REQ         ::= SEQUENCE {
///        -- NOTE: first tag is [1], not [0]
///        pvno            [1] INTEGER (5) ,
///        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
///        padata          [3] SEQUENCE OF PA-DATA OPTIONAL
///                            -- NOTE: not empty --,
///        req-body        [4] KDC-REQ-BODY
/// }
/// ```

#[derive(Sequence, Debug, PartialEq, Clone)]
#[seq(application_tag = 10)]
pub struct AsReq {
    #[seq_field(context_tag = 1)]
    pub pvno: Int32,
    #[seq_field(context_tag = 2)]
    pub msg_type: Int32,
    #[seq_field(context_tag = 3)]
    pub padata: Option<SequenceOf<PaData>>,
    #[seq_field(context_tag = 4)]
    pub req_body: KdcReqBody,
}

impl Default for AsReq {
    fn default() -> Self {
        return Self {
            pvno: 5,
            msg_type: 10,
            padata: Option::default(),
            req_body: KdcReqBody::default()
        }
    }
}

impl From<KdcReq> for AsReq {
    fn from(req: KdcReq) -> Self {
        Self {
            pvno: req.pvno,
            msg_type: 10,
            padata: req.padata,
            req_body: req.req_body
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::address_types::NETBIOS;
    use kerberos_constants::etypes::*;
    use kerberos_constants::kdc_options::*;
    use kerberos_constants::principal_names::*;
    use kerberos_constants::pa_data_types::PA_PAC_REQUEST;
    use crate::{padd_netbios_string, HostAddress};
    use chrono::prelude::*;
    use crate::{PrincipalName, KerberosTime, KdcOptions, PaData, KerbPaPacRequest};

    #[test]
    fn test_build_as_req() {
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


        let mut as_req = AsReq::default();
        as_req.req_body = kdc_req_body;
        as_req.padata = Some(vec![PaData::new(PA_PAC_REQUEST, KerbPaPacRequest::new(true).build())]);
        
        assert_eq!(
            vec![
                0x6a, 0x81, 0xe3, 0x30, 0x81, 0xe0, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x03, 0x02,
                0x01, 0x0a, 0xa3, 0x15, 0x30, 0x13, 0x30, 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80,
                0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff, 0xa4, 0x81, 0xbc,
                0x30, 0x81, 0xb9, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10, 0xa1, 0x13,
                0x30, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d,
                0x69, 0x63, 0x6b, 0x65, 0x79, 0xa2, 0x10, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44,
                0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa3, 0x23, 0x30, 0x21, 0xa0,
                0x03, 0x02, 0x01, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74,
                0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45,
                0x41, 0x52, 0x54, 0x53, 0xa5, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x37, 0x30, 0x39,
                0x31, 0x33, 0x30, 0x32, 0x34, 0x38, 0x30, 0x35, 0x5a, 0xa6, 0x11, 0x18, 0x0f, 0x32,
                0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33, 0x30, 0x32, 0x34, 0x38, 0x30, 0x35, 0x5a,
                0xa7, 0x06, 0x02, 0x04, 0x06, 0x08, 0x95, 0xb6, 0xa8, 0x15, 0x30, 0x13, 0x02, 0x01,
                0x12, 0x02, 0x01, 0x11, 0x02, 0x01, 0x17, 0x02, 0x01, 0x18, 0x02, 0x02, 0xff, 0x79,
                0x02, 0x01, 0x03, 0xa9, 0x1d, 0x30, 0x1b, 0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14,
                0xa1, 0x12, 0x04, 0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x42, 0x41, 0x53, 0x54,
                0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20
            ],
            as_req.build()
        );
    }
}
