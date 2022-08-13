
/// (*UInt32*) Kerberos u32.
/// Defined RFC4120, section 5.2.4.
/// ```asn1
/// UInt32          ::= INTEGER (0..4294967295)
///                    -- unsigned 32 bit values
/// ```
pub type UInt32 = u32;

#[cfg(test)]
mod test {
    use super::UInt32;
    use red_asn1::Asn1Object;

    #[test]
    fn test_encode_uint32() {
        assert_eq!(
            vec![0x02, 0x04, 0x06, 0x08, 0x95, 0xb6],
            (101225910 as u32).build()
        );

        assert_eq!(
            vec![0x02, 0x04, 0xc1, 0x75, 0xc7, 0xce],
            (3245721550 as u32).build()
        );
    }

    #[test]
    fn test_decode_uint32() {
        assert_eq!(
            101225910,
            UInt32::parse(&[0x02, 0x04, 0x06, 0x08, 0x95, 0xb6])
                .unwrap()
                .1
        );

        assert_eq!(
            3245721550,
            UInt32::parse(&[0x02, 0x04, 0xc1, 0x75, 0xc7, 0xce])
                .unwrap()
                .1
        )
    }
}
