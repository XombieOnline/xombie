use crate::CountedOctetString;
use kerberos_asn1::KerberosString;
use crate::{ConvertResult};

pub fn kerberos_string_to_counted_octet_string(
    kerberos_string: &KerberosString,
) -> CountedOctetString {
    return CountedOctetString::new(kerberos_string.as_bytes().to_vec());
}

pub fn counted_octet_string_to_kerberos_string(
    counted_octet_string: CountedOctetString,
) -> ConvertResult<KerberosString> {
    return Ok(KerberosString::from_utf8(counted_octet_string.data)?);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_kerberos_string_to_counted_octet_string() {
        let cos_string = kerberos_string_to_counted_octet_string(
            &KerberosString::from("ABC"),
        );

        assert_eq!(CountedOctetString::from("ABC"), cos_string);
    }

    #[test]
    fn test_counted_octet_string_to_kerberos_string() {
        let k_string: KerberosString = counted_octet_string_to_kerberos_string(
            CountedOctetString::from("ABC"),
        )
        .unwrap();

        assert_eq!(KerberosString::from("ABC"), k_string)
    }

    #[test]
    #[should_panic(expected = "FromUtf8Error")]
    fn test_counted_octet_string_to_kerberos_string_fail() {
        counted_octet_string_to_kerberos_string(CountedOctetString::new(vec![
            0xff,
        ]))
        .unwrap();
    }
}
