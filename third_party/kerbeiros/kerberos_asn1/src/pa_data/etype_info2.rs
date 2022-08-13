use red_asn1::SequenceOf;
use crate::EtypeInfo2Entry;

/// (*ETYPE-INFO2*) Array of [EtypeInfo2Entry](./struct.EtypeInfo2Entry.html)
/// that indicates the available encryption algorithms.
///
/// ```asn1
/// ETYPE-INFO2              ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY
/// ```
pub type EtypeInfo2 = SequenceOf<EtypeInfo2Entry>;

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::etypes::*;
    use crate::KerberosString;
    use red_asn1::Asn1Object;

    #[test]
    fn test_parse_etypeinfo2() {
        let entry1 = EtypeInfo2Entry::new(
            AES256_CTS_HMAC_SHA1_96,
            Some(KerberosString::from("KINGDOM.HEARTSmickey")),
            None
        );

        let entry2 = EtypeInfo2Entry::new(RC4_HMAC, None, None);

        let entry3 = EtypeInfo2Entry::new(
            DES_CBC_MD5,
            Some(KerberosString::from("KINGDOM.HEARTSmickey")),
            None
        );

        let mut info2 = EtypeInfo2::default();
        info2.push(entry1);
        info2.push(entry2);
        info2.push(entry3);

        assert_eq!(
            info2,
            EtypeInfo2::parse(&[
                0x30, 0x45, 0x30, 0x1d, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x16, 0x1b, 0x14, 0x4b,
                0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d,
                0x69, 0x63, 0x6b, 0x65, 0x79, 0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x17, 0x30, 0x1d,
                0xa0, 0x03, 0x02, 0x01, 0x03, 0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 0x44,
                0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65,
                0x79,
            ]).unwrap().1
        );
    }


    #[test]
    fn test_build_etypeinfo2() {
        let entry1 = EtypeInfo2Entry::new(
            AES256_CTS_HMAC_SHA1_96,
            Some(KerberosString::from("KINGDOM.HEARTSmickey")),
            None
        );

        let entry2 = EtypeInfo2Entry::new(RC4_HMAC, None, None);

        let entry3 = EtypeInfo2Entry::new(
            DES_CBC_MD5,
            Some(KerberosString::from("KINGDOM.HEARTSmickey")),
            None
        );

        let mut info2 = EtypeInfo2::default();
        info2.push(entry1);
        info2.push(entry2);
        info2.push(entry3);

        assert_eq!(
            vec![
                0x30, 0x45, 0x30, 0x1d, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x16, 0x1b, 0x14, 0x4b,
                0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d,
                0x69, 0x63, 0x6b, 0x65, 0x79, 0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x17, 0x30, 0x1d,
                0xa0, 0x03, 0x02, 0x01, 0x03, 0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 0x44,
                0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65,
                0x79,
            ],
            info2.build()
        );
    }
}
