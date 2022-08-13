use crate::error as asn1err;
use crate::length::{parse_length, build_length};
use crate::tag::Tag;
use crate::traits::Asn1Object;

/// Class to build/parse SequenceOf ASN1
pub type Optional<T> = Option<T>;

impl<T: Asn1Object> Asn1Object for Option<T> {
    fn build(&self) -> Vec<u8> {
        if let Some(value) = self {
            let mut built = Self::tag().build();
            let mut built_value = value.build_value();
            let mut built_length = build_length(built_value.len());
            built.append(&mut built_length);
            built.append(&mut built_value);

            return built;
        }

        return Vec::new();
    }

    fn parse(raw: &[u8]) -> asn1err::Result<(&[u8], Self)> {
        let parsed_tag;
        let raw_local;
        match Tag::parse(raw) {
            Err(_) => return Ok((raw, None)),
            Ok((raw_tmp, tag)) => {
                raw_local = raw_tmp;
                parsed_tag = tag;
            }
        }

        if parsed_tag != Self::tag() {
            return Ok((raw, None));
        }

        let (raw_local, length) = parse_length(raw_local)?;
        if length > raw_local.len() {
            return Err(asn1err::Error::NoDataForLength)?;
        }

        let (raw_value, raw_local) = raw_local.split_at(length);
        let mut asn1obj = T::default();
        asn1obj.parse_value(raw_value)?;

        return Ok((raw_local, Some(asn1obj)));
    }

    fn tag() -> Tag {
        return T::tag();
    }

    fn build_value(&self) -> Vec<u8> {
        unimplemented!()
    }

    fn parse_value(&mut self, _: &[u8]) -> asn1err::Result<()> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GeneralString, Integer};

    #[test]
    fn test_build_optional_some() {
        assert_eq!(vec![0x2, 0x1, 0x1], Some(Integer::from(1)).build());
        assert_eq!(
            vec![
                0x1b, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x40, 0x72, 0x73,
                0x61, 0x2e, 0x63, 0x6f, 0x6d
            ],
            Some(GeneralString::from("test1@rsa.com")).build()
        );
    }

    #[test]
    fn test_build_none() {
        let o: Option<Integer> = None;
        assert_eq!(Vec::<u8>::new(), o.build());
    }

    #[test]
    fn test_parse_optional_some() {
        assert_eq!(
            Some(Integer::from(1)),
            Option::<Integer>::parse(&[0x2, 0x1, 0x1]).unwrap().1
        );
        assert_eq!(
            Some(GeneralString::from("test1@rsa.com")),
            Option::<GeneralString>::parse(&[
                0x1b, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x40, 0x72, 0x73,
                0x61, 0x2e, 0x63, 0x6f, 0x6d
            ])
            .unwrap()
            .1
        );
    }


    #[test]
    fn test_parse_none_mismatch_tag() {
        let o: Option<Integer> = None;
        let rest: &[u8] = &[0x3, 0x0];
        assert_eq!((rest, o), Option::<Integer>::parse(&[0x3, 0x0]).unwrap());
    }

    #[test]
    fn test_parse_none_no_data() {
        let o: Option<Integer> = None;
        assert_eq!(o, Option::<Integer>::parse(&[]).unwrap().1);
    }

    #[test]
    #[should_panic(expected = "NoDataForLength")]
    fn test_parse_none_no_type_data() {
        Option::<Integer>::parse(&[0x2, 0x3]).unwrap();
    }

    #[test]
    #[should_panic(expected = "NotEnoughLengthOctects")]
    fn test_parse_option_invalid_length() {
        Option::<Integer>::parse(&[0x2, 0xff]).unwrap();
    }
}
