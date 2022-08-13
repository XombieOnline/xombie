use crate::KerberosFlags;
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*PA-PAC-OPTIONS*) To request options of the PAC.
/// Defined in MS-KILE, section 2.2.10 and MS-SFU, section 2.2.5.
/// ```asn1
/// PA-PAC-OPTIONS ::= SEQUENCE {
///     KerberosFlags
///       --Claims (0)
///       --Branch Aware (1)
///       --Forward to Full DC (2)
///       -- resource-based constrained delegation (3)
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct PaPacOptions {
    #[seq_field(context_tag = 0)]
    pub kerberos_flags: KerberosFlags,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_pa_pac_options() {
        let options = PaPacOptions {
            kerberos_flags: 0x10000000.into(),
        };
        assert_eq!(
            vec![
                0x30, 0x09, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x10, 0x00, 0x00,
                0x00
            ],
            options.build()
        )
    }

    #[test]
    fn test_parse_pa_pac_options() {
        let options = PaPacOptions {
            kerberos_flags: 0x10000000.into(),
        };
        assert_eq!(
            options,
            PaPacOptions::parse(&[
                0x30, 0x09, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x10, 0x00, 0x00,
                0x00
            ])
            .unwrap()
            .1
        )
    }
}
