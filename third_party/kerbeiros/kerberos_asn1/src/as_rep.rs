use crate::{EncryptedData, Int32, PaData, PrincipalName, Realm, Ticket};
use red_asn1::{Asn1Object, SequenceOf};
use red_asn1_derive::Sequence;

/// (*AS-REP*) Message returned by KDC in response to AS-REQ.
/// ```asn1
/// AS-REP          ::= [APPLICATION 11] KDC-REP
///
/// KDC-REP         ::= SEQUENCE {
///        pvno            [0] INTEGER (5),
///        msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
///        padata          [2] SEQUENCE OF PA-DATA OPTIONAL
///                                -- NOTE: not empty --,
///        crealm          [3] Realm,
///        cname           [4] PrincipalName,
///        ticket          [5] Ticket,
///        enc-part        [6] EncryptedData
///                                -- EncASRepPart or EncTGSRepPart,
///                                -- as appropriate
/// }
/// ```
#[derive(Sequence, Debug, Clone, PartialEq)]
#[seq(application_tag = 11)]
pub struct AsRep {
    #[seq_field(context_tag = 0)]
    pub pvno: Int32,
    #[seq_field(context_tag = 1)]
    pub msg_type: Int32,
    #[seq_field(context_tag = 2)]
    pub padata: Option<SequenceOf<PaData>>,
    #[seq_field(context_tag = 3)]
    pub crealm: Realm,
    #[seq_field(context_tag = 4)]
    pub cname: PrincipalName,
    #[seq_field(context_tag = 5)]
    pub ticket: Ticket,
    #[seq_field(context_tag = 6)]
    pub enc_part: EncryptedData,
}

impl Default for AsRep {
    fn default() -> Self {
        return Self {
            pvno: 5,
            msg_type: 11,
            padata: Option::default(),
            crealm: Realm::default(),
            cname: PrincipalName::default(),
            ticket: Ticket::default(),
            enc_part: EncryptedData::default(),
        };
    }
}

impl AsRep {
    pub fn new(
        padata: Option<SequenceOf<PaData>>,
        crealm: Realm,
        cname: PrincipalName,
        ticket: Ticket,
        enc_part: EncryptedData,
    ) -> Self {
        return Self {
            pvno: 5,
            msg_type: 11,
            padata,
            crealm,
            cname,
            ticket,
            enc_part,
        };
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::etypes::*;
    use kerberos_constants::pa_data_types::PA_ETYPE_INFO2;
    use kerberos_constants::principal_names::*;
    use crate::{EtypeInfo2Entry, KerberosString};

    #[test]
    fn decode_as_rep() {
        let encoded_as_rep = [
            0x6b, 0x81, 0xcc, 0x30, 0x81, 0xc9, 0xa0, 0x03, 0x02, 0x01, 0x05,
            0xa1, 0x03, 0x02, 0x01, 0x0b, 0xa2, 0x2e, 0x30, 0x2c, 0x30, 0x2a,
            0xa1, 0x03, 0x02, 0x01, 0x13, 0xa2, 0x23, 0x04, 0x21, 0x30, 0x1f,
            0x30, 0x1d, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x16, 0x1b, 0x14,
            0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41,
            0x52, 0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79, 0xa3, 0x10,
            0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48,
            0x45, 0x41, 0x52, 0x54, 0x53, 0xa4, 0x13, 0x30, 0x11, 0xa0, 0x03,
            0x02, 0x01, 0x01, 0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d, 0x69,
            0x63, 0x6b, 0x65, 0x79, 0xa5, 0x53, 0x61, 0x51, 0x30, 0x4f, 0xa0,
            0x03, 0x02, 0x01, 0x05, 0xa1, 0x10, 0x1b, 0x0e, 0x4b, 0x49, 0x4e,
            0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
            0xa2, 0x23, 0x30, 0x21, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1a,
            0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b,
            0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45,
            0x41, 0x52, 0x54, 0x53, 0xa3, 0x11, 0x30, 0x0f, 0xa0, 0x03, 0x02,
            0x01, 0x12, 0xa1, 0x03, 0x02, 0x01, 0x02, 0xa2, 0x03, 0x04, 0x01,
            0x9, 0xa6, 0x11, 0x30, 0x0f, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1,
            0x03, 0x02, 0x01, 0x02, 0xa2, 0x03, 0x04, 0x01, 0x9,
        ];

        let sname_ticket = PrincipalName {
            name_type: NT_SRV_INST,
            name_string: vec![
                KerberosString::from("krbtgt"),
                KerberosString::from("KINGDOM.HEARTS"),
            ],
        };

        let encrypted_data = EncryptedData {
            etype: AES256_CTS_HMAC_SHA1_96,
            kvno: Some(2),
            cipher: vec![0x9],
        };

        let ticket = Ticket::new(
            Realm::from("KINGDOM.HEARTS"),
            sname_ticket,
            encrypted_data.clone(),
        );

        let entry1 = EtypeInfo2Entry {
            etype: AES256_CTS_HMAC_SHA1_96,
            salt: Some(KerberosString::from("KINGDOM.HEARTSmickey")),
            s2kparams: None,
        };

        let info2 = vec![entry1];

        let mut as_rep = AsRep::default();
        as_rep.crealm = Realm::from("KINGDOM.HEARTS");
        as_rep.cname =
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from("mickey"));
        as_rep.ticket = ticket;
        as_rep.enc_part = encrypted_data;
        as_rep.padata = Some(vec![PaData {
            padata_type: PA_ETYPE_INFO2,
            padata_value: info2.build(),
        }]);

        assert_eq!(as_rep, AsRep::parse(&encoded_as_rep).unwrap().1);
    }
}
