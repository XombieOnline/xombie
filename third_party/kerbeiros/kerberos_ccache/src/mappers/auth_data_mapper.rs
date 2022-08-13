use crate::{AuthData, CountedOctetString};
use kerberos_asn1::{MethodData, PaData};

pub fn padata_to_auth_data(padata: &PaData) -> AuthData {
    return AuthData::new(
        padata.padata_type as u16,
        CountedOctetString::new(padata.padata_value.clone()),
    );
}

pub fn method_data_to_auth_data_vector(
    method_data: &MethodData,
) -> Vec<AuthData> {
    let mut auth_data = Vec::new();
    for padata in method_data.iter() {
        auth_data.push(padata_to_auth_data(padata));
    }
    return auth_data;
}

pub fn auth_data_to_padata(auth_data: AuthData) -> PaData {
    return PaData::new(auth_data.addrtype as i32, auth_data.addrdata.data);
}

pub fn auth_data_vector_to_method_data(
    auth_datas: Vec<AuthData>,
) -> MethodData {
    return auth_datas
        .into_iter()
        .map(|auth_data| auth_data_to_padata(auth_data))
        .collect();
}

#[cfg(test)]
mod test {
    use super::*;
    use kerberos_asn1::{Asn1Object, KerbPaPacRequest};
    use crate::Address;
    use kerberos_constants::pa_data_types::*;

    #[test]
    fn test_padata_to_auth_data() {
        let padata =
            PaData::new(PA_PAC_REQUEST, KerbPaPacRequest::new(true).build());

        let auth_data = AuthData::new(
            PA_PAC_REQUEST as u16,
            CountedOctetString::new(vec![
                0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff,
            ]),
        );

        assert_eq!(auth_data, padata_to_auth_data(&padata));
    }

    #[test]
    fn test_method_data_to_auth_data_vector() {
        let mut auth_datas = Vec::new();
        auth_datas.push(AuthData::new(
            PA_PAC_REQUEST as u16,
            CountedOctetString::new(vec![
                0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff,
            ]),
        ));
        auth_datas
            .push(Address::new(9, CountedOctetString::new(vec![0x8, 0x9])));

        let mut method_data = MethodData::default();
        method_data.push(PaData::new(
            PA_PAC_REQUEST,
            KerbPaPacRequest::new(true).build(),
        ));
        method_data.push(PaData::new(9, vec![0x8, 0x9]));

        assert_eq!(
            auth_datas,
            method_data_to_auth_data_vector(&method_data)
        );
    }

    #[test]
    fn test_auth_data_to_padata() {
        let padata =
            PaData::new(PA_PAC_REQUEST, KerbPaPacRequest::new(true).build());

        let auth_data = AuthData::new(
            PA_PAC_REQUEST as u16,
            CountedOctetString::new(vec![
                0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff,
            ]),
        );

        assert_eq!(padata, auth_data_to_padata(auth_data));
    }

    #[test]
    fn test_auth_data_vector_to_method_data() {
        let mut auth_datas = Vec::new();
        auth_datas.push(AuthData::new(
            PA_PAC_REQUEST as u16,
            CountedOctetString::new(vec![
                0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff,
            ]),
        ));
        auth_datas
            .push(Address::new(9, CountedOctetString::new(vec![0x8, 0x9])));

        let mut method_data = MethodData::default();
        method_data.push(PaData::new(
            PA_PAC_REQUEST,
            KerbPaPacRequest::new(true).build(),
        ));
        method_data.push(PaData::new(9, vec![0x8, 0x9]));

        assert_eq!(
            method_data,
            auth_data_vector_to_method_data(auth_datas)
        );
    }
}
