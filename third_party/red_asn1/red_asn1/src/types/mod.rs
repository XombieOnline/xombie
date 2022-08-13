mod bitstring;
pub use bitstring::*;

mod boolean;
pub use boolean::*;

mod generalizedtime;
pub use generalizedtime::{GeneralizedTime, GENERALIZED_TIME_TAG_NUMBER};

mod generalstring;
pub use generalstring::*;

mod ia5string;
pub use ia5string::*;

mod enumerated;
pub use enumerated::{Enumerated, ENUMERATED_TAG_NUMBER};

mod integer;
pub use integer::*;

mod octetstring;
pub use octetstring::*;

mod oid;
pub use oid::Oid;

mod sequenceof;
pub use sequenceof::*;

mod optional;
pub use optional::Optional;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::*;

    #[test]
    fn test_build_common_tags() {
        assert_eq!(vec![0x01], Boolean::tag().build());
        assert_eq!(vec![0x02], Integer::tag().build());
        assert_eq!(vec![0x03], BitString::tag().build());
        assert_eq!(vec![0x04], OctetString::tag().build());
        assert_eq!(vec![0x0a], Enumerated::<u32>::tag().build());
        assert_eq!(vec![0x30], SequenceOf::<Integer>::tag().build());
        assert_eq!(vec![0x16], IA5String::tag().build());
        assert_eq!(vec![0x18], GeneralizedTime::tag().build());
    }
}
