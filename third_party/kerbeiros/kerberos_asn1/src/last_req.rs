use crate::{Int32, KerberosTime};
use red_asn1::{Asn1Object, SequenceOf};
use red_asn1_derive::Sequence;

/// (*LastReq*) Register of time of a request to KDC.
/// Defined in RFC4120, 5.4.2.
/// ```asn1
/// LastReq         ::=     SEQUENCE OF SEQUENCE {
///        lr-type         [0] Int32,
///        lr-value        [1] KerberosTime
/// }
/// ```
pub type LastReq = SequenceOf<LastReqEntry>;


/// Entry of *LastReq*.
/// Pseudotype defined in this library.
/// Defined in RFC4120, 5.4.2.
/// ```asn1
/// LastReq         ::=     SEQUENCE OF SEQUENCE {
///        lr-type         [0] Int32,
///        lr-value        [1] KerberosTime
/// }
/// ```
#[derive(Sequence, Default, Debug, PartialEq, Clone)]
pub struct LastReqEntry {
    #[seq_field(context_tag = 0)]
    pub lr_type: Int32,
    #[seq_field(context_tag = 1)]
    pub lr_value: KerberosTime,
}

impl LastReqEntry {
    pub fn new(lr_type: Int32, lr_value: KerberosTime) -> Self {
        return Self { lr_type, lr_value };
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;

    #[test]
    fn test_parse_last_req() {
        let raw: Vec<u8> = vec![
            0x30, 0x1a, 0x30, 0x18, 0xa0, 0x03, 0x02, 0x01, 0x00, 0xa1, 0x11,
            0x18, 0x0f, 0x32, 0x30, 0x31, 0x39, 0x30, 0x34, 0x31, 0x38, 0x30,
            0x36, 0x30, 0x30, 0x33, 0x31, 0x5a,
        ];

        let last_req = vec![LastReqEntry {
            lr_type: 0,
            lr_value: KerberosTime::from(
                Utc.ymd(2019, 4, 18).and_hms(06, 00, 31),
            ),
        }];

        assert_eq!(last_req, LastReq::parse(&raw).unwrap().1);
    }
}
