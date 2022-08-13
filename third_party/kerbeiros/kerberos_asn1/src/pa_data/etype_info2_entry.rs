use crate::{Int32, KerberosString};
use red_asn1::{Asn1Object, OctetString};
use red_asn1_derive::Sequence;

/// (*ETYPE-INFO2-ENTRY*) Give information about an encryption algorithm.
/// ```asn1
/// ETYPE-INFO2-ENTRY       ::= SEQUENCE {
///        etype           [0] Int32,
///        salt            [1] KerberosString OPTIONAL,
///        s2kparams       [2] OCTET STRING OPTIONAL
/// }
/// ```

#[derive(Sequence, Debug, Clone, PartialEq, Default)]
pub struct EtypeInfo2Entry {
    #[seq_field(context_tag = 0)]
    pub etype: Int32,
    #[seq_field(context_tag = 1)]
    pub salt: Option<KerberosString>,
    #[seq_field(context_tag = 2)]
    pub s2kparams: Option<OctetString>,
}

impl EtypeInfo2Entry {
    pub fn new(etype: Int32, salt: Option<KerberosString>, s2kparams: Option<OctetString>) -> Self {
        return Self {
            etype,
            salt,
            s2kparams,
        };
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::etypes::*;

    #[test]
    fn test_parse_etypeinfo2entry() {
        let mut entry = EtypeInfo2Entry::default();
        entry.etype = AES256_CTS_HMAC_SHA1_96;
        entry.salt = Some(KerberosString::from("KINGDOM.HEARTSmickey"));

        assert_eq!(
            entry,
            EtypeInfo2Entry::parse(&[
                0x30, 0x1d, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e,
                0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d, 0x69, 0x63,
                0x6b, 0x65, 0x79,
            ])
            .unwrap()
            .1
        );
    }


    #[test]
    fn test_build_etypeinfo2entry() {
        let mut entry = EtypeInfo2Entry::default();
        entry.etype = AES256_CTS_HMAC_SHA1_96;
        entry.salt = Some(KerberosString::from("KINGDOM.HEARTSmickey"));

        assert_eq!(
            vec![
                0x30, 0x1d, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e,
                0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d, 0x69, 0x63,
                0x6b, 0x65, 0x79,
            ],
            entry.build()
        );
    }
}
