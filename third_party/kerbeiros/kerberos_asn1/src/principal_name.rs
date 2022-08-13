use super::{Int32, KerberosString};
use red_asn1_derive::Sequence;
use red_asn1::Asn1Object;
use std::fmt;

/// (*PrincipalName*) Name of some Kerberos entity.
///
/// ```asn1
/// PrincipalName ::= SEQUENCE {
///         name-type     [0] Int32,
///         name-string   [1] SEQUENCE OF KerberosString
/// }
/// ```
/// Used for client name and service name.
#[derive(Sequence, Default, Debug, Clone)]
pub struct PrincipalName {
    #[seq_field(context_tag = 0)]
    pub name_type: Int32,
    #[seq_field(context_tag = 1)]
    pub name_string: Vec<KerberosString>,
}

impl PrincipalName {
    pub fn new(name_type: i32, string: KerberosString) -> PrincipalName {
        let mut principal_name = PrincipalName {
            name_type: name_type,
            name_string: Vec::new(),
        };

        principal_name.name_string.push(string);

        return principal_name;
    }

    pub fn main_name(&self) -> &KerberosString {
        return &self.name_string[0];
    }
    pub fn push(&mut self, string: KerberosString) {
        self.name_string.push(string);
    }

    pub fn to_string(&self) -> String {
        let mut names = self.main_name().to_string();

        for name in self.name_string[1..].iter() {
            names += &format!("/{}", name);
        }

        return names;
    }
}

impl PartialEq<PrincipalName> for PrincipalName {

    /// String case insensitive comparison
    fn eq(&self, other: &PrincipalName) -> bool {
        if self.name_type != other.name_type {
            return false;
        }

        if self.name_string.len() != other.name_string.len() {
            return false;
        }

        for (s1, s2) in self.name_string.iter().zip(other.name_string.iter()) {
            if s1.as_str().to_lowercase() != s2.as_str().to_lowercase() {
                return false;
            }
        }

        return true;
    }
}

impl fmt::Display for PrincipalName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerberos_constants::principal_names::*;

    #[test]
    fn test_principal_name_partial_eq() {
        let pn1 = PrincipalName {
            name_type: 0,
            name_string: vec!["AAA".into()]
        };

        let pn2 = PrincipalName {
            name_type: 0,
            name_string: vec!["AAA".into(), "BBB".into()]
        };

        let pn3 = PrincipalName {
            name_type: 0,
            name_string: vec!["aaa".into()]
        };

        let pn4 = PrincipalName {
            name_type: 0,
            name_string: vec!["bbb".into()]
        };

        assert_ne!(pn1, pn2);
        assert_eq!(pn1, pn3);
        assert_ne!(pn1, pn4);
    }
    
    #[test]
    fn test_encode_principal_name() {
        let principal_name =
            PrincipalName::new(NT_PRINCIPAL, "mickey".to_string());

        assert_eq!(
            vec![
                0x30, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d,
                0x69, 0x63, 0x6b, 0x65, 0x79
            ],
            principal_name.build()
        )
    }

    #[test]
    fn test_encode_many_principal_name_strings() {
        let mut principal_name =
            PrincipalName::new(NT_SRV_INST, "krbtgt".to_string());
        principal_name.push(KerberosString::from("KINGDOM.HEARTS"));

        assert_eq!(
            vec![
                0x30, 0x21, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b,
                0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d,
                0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53
            ],
            principal_name.build()
        )
    }

    #[test]
    fn test_decode_principal_name() {
        assert_eq!(
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from("mickey")),
            PrincipalName::parse(&[
                0x30, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d,
                0x69, 0x63, 0x6b, 0x65, 0x79,
            ]).unwrap().1
        );
    }

    #[test]
    fn test_decode_many_principal_name_strings() {
        let mut principal_name =
            PrincipalName::new(NT_SRV_INST, KerberosString::from("krbtgt"));
        principal_name.push(KerberosString::from("KINGDOM.HEARTS"));

        assert_eq!(principal_name, PrincipalName::parse(&[
                0x30, 0x21, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b,
                0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d,
                0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
            ]).unwrap().1);
    }

    #[test]
    fn principal_name_get_main_name_one_string() {
        let main_name = KerberosString::from("krbtgt");
        let principal_name = PrincipalName::new(NT_SRV_INST, main_name.clone());

        assert_eq!(&main_name, principal_name.main_name())
    }

    #[test]
    fn principal_name_get_main_name_many_strings() {
        let main_name = KerberosString::from("krbtgt");
        let mut principal_name = PrincipalName::new(NT_SRV_INST, main_name.clone());
        principal_name.push(KerberosString::from("KINGDOM.HEARTS"));

        assert_eq!(&main_name, principal_name.main_name())
    }

    #[test]
    fn principal_name_to_string_with_one_string() {
        let main_name = KerberosString::from("krbtgt");
        let principal_name = PrincipalName::new(NT_SRV_INST, main_name.clone());

        assert_eq!("krbtgt".to_string(), principal_name.to_string())
    }

    #[test]
    fn principal_name_to_string_with_many_strings() {
        let main_name = KerberosString::from("krbtgt");
        let mut principal_name = PrincipalName::new(NT_SRV_INST, main_name.clone());
        principal_name.push(KerberosString::from("KINGDOM.HEARTS"));

        assert_eq!(
            "krbtgt/KINGDOM.HEARTS".to_string(),
            principal_name.to_string()
        )
    }
}
