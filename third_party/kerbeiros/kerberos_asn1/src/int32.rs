
/// (*Int32*) Kerberos i32.
/// Defined in RFC4120, section 5.2.4.
/// ```asn1
///    Int32           ::= INTEGER (-2147483648..2147483647)
///                    -- signed values representable in 32 bits
/// ```
pub type Int32 = i32;

#[cfg(test)]
mod test {
    use super::*;
    use red_asn1::Asn1Object;

    #[test]
    fn test_encode_int32() {
        assert_eq!(vec![0x02, 0x02, 0xff, 0x79], Int32::from(-135).build());

        assert_eq!(vec![0x02, 0x01, 0x03], Int32::from(3).build());
    }

    #[test]
    fn test_decode_int32() {
        assert_eq!(-135, Int32::parse(&[0x02, 0x02, 0xff, 0x79]).unwrap().1);

        assert_eq!(3, Int32::parse(&[0x02, 0x01, 0x03]).unwrap().1);
    }

    #[should_panic(expected = "IncorrectValue")]
    #[test]
    fn test_decode_higher_value_than_int32() {
        Int32::parse(&[0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]).unwrap();
    }

    #[should_panic(expected = "IncorrectValue")]
    #[test]
    fn test_decode_lower_value_than_int32() {
        Int32::parse(&[0x02, 0x05, 0xf1, 0x00, 0x00, 0x00, 0x00]).unwrap();
    }

}
