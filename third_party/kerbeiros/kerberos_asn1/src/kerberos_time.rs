use chrono::prelude::{DateTime, Datelike, TimeZone, Timelike, Utc};
use red_asn1::{Asn1Object, GeneralizedTime, Tag};
use std::ops::{Deref, DerefMut};

/// (*KerberosTime*) For time representations in Kerberos.
/// ```asn1
/// KerberosTime    ::= GeneralizedTime -- with no fractional seconds
/// ```

#[derive(Default, Debug, Clone, PartialEq)]
pub struct KerberosTime {
    pub time: GeneralizedTime,
}

impl Deref for KerberosTime {
    type Target = GeneralizedTime;
    fn deref(&self) -> &Self::Target {
        &self.time
    }
}

impl DerefMut for KerberosTime {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.time
    }
}

impl Asn1Object for KerberosTime {
    fn tag() -> Tag {
        return GeneralizedTime::tag();
    }

    fn parse_value(&mut self, raw: &[u8]) -> red_asn1::Result<()> {
        return self.time.parse_value(raw);
    }

    // Overwrite function to produce an DER encoding
    // without fractional seconds, as specified in the RFC
    fn build_value(&self) -> Vec<u8> {
        let time_no_nanos =
            GeneralizedTime::from(Utc.ymd(self.year(), self.month(), self.day()).and_hms(
                self.hour(),
                self.minute(),
                self.second(),
            ));
        return time_no_nanos.build_value();
    }
}

impl From<DateTime<Utc>> for KerberosTime {
    fn from(time: DateTime<Utc>) -> Self {
        return Self {
            time: GeneralizedTime::from(time),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_asn1::Asn1Object;

    #[test]
    fn test_encode_kerberos_time() {
        assert_eq!(
            vec![
                0x18, 0x0f, 0x32, 0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33, 0x30, 0x32, 0x34, 0x38,
                0x30, 0x35, 0x5a
            ],
            KerberosTime::from(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5)).build()
        );
    }

    #[test]
    fn test_decode_kerberos_time() {
        assert_eq!(
            Utc.ymd(2037, 9, 13).and_hms(02, 48, 5),
            **KerberosTime::parse(&[
                0x18, 0x0f, 0x32, 0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33, 0x30, 0x32, 0x34, 0x38,
                0x30, 0x35, 0x5a,
            ])
            .unwrap()
            .1
        );
    }
}
