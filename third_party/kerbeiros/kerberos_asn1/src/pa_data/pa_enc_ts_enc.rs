use crate::{KerberosTime, Microseconds, MAX_MICROSECONDS, MIN_MICROSECONDS};
use chrono::prelude::*;
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*PA-ENC-TS-ENC*) Timestamp that is encrypted with client [Key](../../key/enum.Key.html).
/// ```asn1
/// PA-ENC-TS-ENC           ::= SEQUENCE {
///            patimestamp     [0] KerberosTime -- client's time --,
///            pausec          [1] Microseconds OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Clone, Debug, PartialEq)]
pub struct PaEncTsEnc {
    #[seq_field(context_tag = 0)]
    pub patimestamp: KerberosTime,
    #[seq_field(context_tag = 1)]
    pub pausec: Option<Microseconds>,
}

impl PaEncTsEnc {
    pub fn new(patimestamp: KerberosTime, pausec: Option<Microseconds>) -> Self {
        return Self {
            patimestamp,
            pausec,
        };
    }
}

impl From<DateTime<Utc>> for PaEncTsEnc {
    fn from(datetime: DateTime<Utc>) -> Self {
        let mut microseconds = datetime.timestamp_subsec_micros() as i32;
        if microseconds > MAX_MICROSECONDS {
            microseconds = MAX_MICROSECONDS;
        }
        else if microseconds < MIN_MICROSECONDS {
            microseconds = MIN_MICROSECONDS
        }

        return Self::new(KerberosTime::from(datetime), Some(microseconds));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_timestamp() {
        let datetime = Utc.ymd(2019, 6, 4).and_hms_micro(05, 22, 12, 143725);
        assert_eq!(
            vec![
                0x30, 0x1a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39, 0x30, 0x36, 0x30, 0x34,
                0x30, 0x35, 0x32, 0x32, 0x31, 0x32, 0x5a, 0xa1, 0x05, 0x02, 0x03, 0x02, 0x31, 0x6d
            ],
            PaEncTsEnc::from(datetime).build()
        );
    }
}
