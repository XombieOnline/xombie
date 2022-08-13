use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*KERB-PA-PAC-REQUEST*) To indicate if PAC should be included in response.
/// Defined in MS-KILE, section 2.2.3.
/// ```asn1
/// KERB-PA-PAC-REQUEST ::= SEQUENCE {
///     include-pac[0] BOOLEAN --If TRUE, and no pac present, include PAC.
///                            --If FALSE, and PAC present, remove PAC
/// }

#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct KerbPaPacRequest {
    #[seq_field(context_tag = 0)]
    pub include_pac: bool,
}

impl KerbPaPacRequest {
    pub fn new(include_pac: bool) -> Self {
        return Self { include_pac };
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_pac_request_true() {
        assert_eq!(
            vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff],
            KerbPaPacRequest::new(true).build()
        );
    }

    #[test]
    fn test_encode_pac_request_false() {
        assert_eq!(
            vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00],
            KerbPaPacRequest::new(false).build()
        );
    }

    #[test]
    fn test_decode_pac_request_true() {
        assert_eq!(
            KerbPaPacRequest::new(true),
            KerbPaPacRequest::parse(&[0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff])
                .unwrap()
                .1
        );
    }

    #[test]
    fn test_decode_pac_request_false() {
        assert_eq!(
            KerbPaPacRequest::new(false),
            KerbPaPacRequest::parse(&[0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00])
                .unwrap()
                .1
        );
    }
}
