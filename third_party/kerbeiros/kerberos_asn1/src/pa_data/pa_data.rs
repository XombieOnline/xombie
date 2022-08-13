use crate::Int32;
use red_asn1::{Asn1Object, OctetString};
use red_asn1_derive::Sequence;

/// (*PA-DATA*) Container that encapsules different types of preauthentication data structures.
/// ```asn1
/// PA-DATA ::= SEQUENCE { -- NOTE: first tag is [1], not [0]
///         padata-type   [1] Int32,
///         padata-value  [2] OCTET STRING -- might be encoded AP-REQ
/// }
/// ```

#[derive(Sequence, Default, Clone, Debug, PartialEq)]
pub struct PaData {
    #[seq_field(context_tag = 1)]
    pub padata_type: Int32,
    #[seq_field(context_tag = 2)]
    pub padata_value: OctetString,
}

impl PaData {
    pub fn new(padata_type: Int32, padata_value: OctetString) -> Self {
        return Self {
            padata_type,
            padata_value,
        };
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_constants::pa_data_types::*;
    use crate::KerbPaPacRequest;

    #[test]
    fn test_build_padata_pac_request() {
        assert_eq!(
            vec![
                0x30, 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xa2, 0x09,
                0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff
            ],
            PaData::new(PA_PAC_REQUEST, KerbPaPacRequest::new(true).build())
                .build()
        );
        assert_eq!(
            vec![
                0x30, 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xa2, 0x09,
                0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00
            ],
            PaData::new(PA_PAC_REQUEST, KerbPaPacRequest::new(false).build())
                .build()
        );
    }

    #[test]
    fn test_decode_padata_pac_request() {
        assert_eq!(
            PaData::new(PA_PAC_REQUEST, KerbPaPacRequest::new(true).build()),
            PaData::parse(&[
                0x30, 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xa2, 0x09,
                0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff,
            ])
            .unwrap()
            .1
        );

        assert_eq!(
            PaData::new(PA_PAC_REQUEST, KerbPaPacRequest::new(false).build()),
            PaData::parse(&[
                0x30, 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xa2, 0x09,
                0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00,
            ])
            .unwrap()
            .1
        );
    }
}
