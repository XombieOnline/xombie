use red_asn1::{Asn1Object, BitString, Tag};
use std::ops::{Deref, DerefMut};

/// (*KerberosFlags*) Flags used for different entities.
/// Defined in RFC4120, section 5.2.8.
/// ```asn1
/// KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
///                     -- minimum number of bits shall be sent,
///                     -- but no fewer than 32
/// ```
#[derive(Debug, PartialEq, Clone, Default)]
pub struct KerberosFlags {
    pub flags: u32,
}

impl Deref for KerberosFlags {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.flags
    }
}

impl DerefMut for KerberosFlags {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.flags
    }
}

impl Asn1Object for KerberosFlags {
    fn tag() -> Tag {
        return BitString::tag();
    }

    fn build_value(&self) -> Vec<u8> {
        let flags_bytes: Vec<u8> = self.flags.to_be_bytes().to_vec();
        return BitString::new(flags_bytes, 0).build_value();
    }

    fn parse_value(&mut self, raw: &[u8]) -> Result<(), red_asn1::Error> {
        let mut bit_string = BitString::default();
        bit_string.parse_value(raw)?;

        let mut bytes = bit_string.bytes;
        let mut i = bytes.len();
        while i < 4 {
            bytes.push(0);
            i += 1;
        }

        let mut array_bytes = [0; 4];
        let array_bytes_len = array_bytes.len();
        array_bytes.copy_from_slice(&bytes[..array_bytes_len]);

        self.flags = u32::from_be_bytes(array_bytes);
        return Ok(());
    }
}

impl From<u32> for KerberosFlags {
    fn from(flags: u32) -> Self {
        return Self { flags };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_asn1::BIT_STRING_TAG_NUMBER;
    use std::u32;

    #[test]
    fn test_create_default_flags() {
        let kdc_flags = KerberosFlags::default();
        assert_eq!(0, kdc_flags.flags);
    }

    #[test]
    fn test_kerberos_flags_from_u32() {
        let test_numbers = vec![0, 1, u32::MAX, 2344, 546];

        for i in test_numbers.iter() {
            let kdc_flags = KerberosFlags::from(*i);
            assert_eq!(*i, kdc_flags.flags);
        }
    }

    #[test]
    fn test_convert_flags_to_bit_string() {
        let kdc_flags = KerberosFlags::from(0x40000000);
        assert_eq!(
            vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x40, 0x0, 0x0, 0x0],
            kdc_flags.build()
        );

        let kdc_flags = KerberosFlags::from(0x01);
        assert_eq!(
            vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0, 0x0, 0x0, 0x1],
            kdc_flags.build()
        );

        let kdc_flags = KerberosFlags::from(0x0000800002);
        assert_eq!(
            vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0, 0x80, 0x0, 0x2],
            kdc_flags.build()
        );

        let kdc_flags = KerberosFlags::from(0x0028144812);
        assert_eq!(
            vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x28, 0x14, 0x48, 0x12],
            kdc_flags.build()
        );
    }

    #[test]
    fn test_decode_kerberos_flags() {
        assert_eq!(
            KerberosFlags::from(0x40000000),
            KerberosFlags::parse(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x40, 0x0, 0x0, 0x0])
                .unwrap()
                .1
        );

        assert_eq!(
            KerberosFlags::from(0x01),
            KerberosFlags::parse(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0, 0x0, 0x0, 0x1])
                .unwrap()
                .1
        );

        assert_eq!(
            KerberosFlags::from(0x0000800002),
            KerberosFlags::parse(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0, 0x80, 0x0, 0x2])
                .unwrap()
                .1
        );

        assert_eq!(
            KerberosFlags::from(0x0028144812),
            KerberosFlags::parse(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x28, 0x14, 0x48, 0x12])
                .unwrap()
                .1
        );
    }

    #[test]
    fn test_decode_short_kerberos_flags() {
        assert_eq!(
            KerberosFlags::from(0x40000000),
            KerberosFlags::parse(&[BIT_STRING_TAG_NUMBER, 0x2, 0x0, 0x40])
                .unwrap()
                .1
        );

        assert_eq!(
            KerberosFlags::from(0x28140000),
            KerberosFlags::parse(&[BIT_STRING_TAG_NUMBER, 0x3, 0x0, 0x28, 0x14])
                .unwrap()
                .1
        );
    }
}
