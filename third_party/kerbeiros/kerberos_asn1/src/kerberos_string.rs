use red_asn1::GeneralString;

/// (*KerberosString*) String used in Kerberos.
/// Defined in RFC4120, section 5.2.1.
/// ```asn1
/// KerberosString  ::= GeneralString (IA5String)
/// ```
pub type KerberosString = GeneralString;

#[cfg(test)]
mod tests {
    use super::*;
    use red_asn1::Asn1Object;

    #[test]
    fn test_encode_kerberos_string() {
        let kerberos_string =
            KerberosString::from("KINGDOM.HEARTS");

        assert_eq!(
            vec![
                0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e,
                0x48, 0x45, 0x41, 0x52, 0x54, 0x53
            ],
            kerberos_string.build()
        );
    }

    #[test]
    fn test_decode_kerberos_string() {
        assert_eq!(
            KerberosString::from("KINGDOM.HEARTS"),
            KerberosString::parse(&[
                0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e,
                0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
            ])
            .unwrap()
            .1
        );
    }

}
