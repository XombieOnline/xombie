use super::{
    counted_octet_string_to_kerberos_string,
    kerberos_string_to_counted_octet_string,
};
use crate::{ConvertError, ConvertResult};
use crate::Principal;
use kerberos_asn1::{PrincipalName, Realm};

pub fn realm_and_principal_name_to_principal(
    realm: &Realm,
    principal_name: &PrincipalName,
) -> Principal {
    let mut components = Vec::new();

    for name in principal_name.name_string.iter() {
        components.push(kerberos_string_to_counted_octet_string(name));
    }

    return Principal::new(
        principal_name.name_type as u32,
        kerberos_string_to_counted_octet_string(realm),
        components,
    );
}

pub fn principal_to_realm_and_principal_name(
    principal: Principal,
) -> ConvertResult<(Realm, PrincipalName)> {
    let components = principal.components;
    let mut names = Vec::with_capacity(components.len());
    for component in components.into_iter() {
        names.push(counted_octet_string_to_kerberos_string(component)?);
    }

    if names.len() == 0 {
        return Err(ConvertError::NoPrincipalName);
    }

    let main_name = names.remove(0);
    let mut principal_name =
        PrincipalName::new(principal.name_type as i32, main_name);

    while names.len() > 0 {
        principal_name.push(names.remove(0));
    }

    let realm = counted_octet_string_to_kerberos_string(principal.realm)?;

    return Ok((realm, principal_name));
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::CountedOctetString;
    use kerberos_asn1::KerberosString;
    use kerberos_constants::principal_names::*;

    #[test]
    fn test_realm_and_principal_name_to_principal() {
        let realm = Realm::from("KINGDOM.HEARTS");
        let principal_name =
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from("mickey"));

        let principal = Principal::new(
            NT_PRINCIPAL as u32,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
            vec![CountedOctetString::new("mickey".as_bytes().to_vec())],
        );

        assert_eq!(
            principal,
            realm_and_principal_name_to_principal(
                &realm,
                &principal_name
            )
        );
    }

    #[test]
    fn test_principal_to_realm_and_principal_name() {
        let realm = Realm::from("KINGDOM.HEARTS");
        let principal_name =
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from("mickey"));

        let principal = Principal::new(
            NT_PRINCIPAL as u32,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
            vec![CountedOctetString::new("mickey".as_bytes().to_vec())],
        );

        assert_eq!(
            (realm, principal_name),
            principal_to_realm_and_principal_name(principal)
                .unwrap(),
        );
    }

    #[test]
    #[should_panic(expected = "NoPrincipalName")]
    fn test_principal_to_realm_and_principal_name_panic() {
        let principal = Principal::new(
            NT_PRINCIPAL as u32,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
            vec![],
        );

        principal_to_realm_and_principal_name(principal)
            .unwrap();
    }

    #[test]
    fn test_principal_to_realm_and_principal_name_multiple_names() {
        let realm = Realm::from("KINGDOM.HEARTS");
        let mut principal_name =
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from("mickey"));

        principal_name.push(KerberosString::from("user2"));

        let principal = Principal::new(
            NT_PRINCIPAL as u32,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
            vec![
                CountedOctetString::new("mickey".as_bytes().to_vec()),
                CountedOctetString::new("user2".as_bytes().to_vec()),
            ],
        );

        assert_eq!(
            (realm, principal_name),
            principal_to_realm_and_principal_name(principal)
                .unwrap(),
        );
    }
}
