use kerberos_asn1::PrincipalName;
use kerberos_constants::*;

pub mod service;

pub const PA_MSKILE_COMPOUND_IDENTITY: i32 = 130;
pub const PA_MSKILE_FOR_CHECK_DUPS:    i32 = 131;
pub const PA_XBOX_SERVICE_REQUEST:     i32 = 201;
pub const PA_XBOX_SERVICE_ADDRESS:     i32 = 202;
pub const PA_XBOX_ACCOUNT_CREATION:    i32 = 203;
pub const PA_XBOX_PPA:                 i32 = 204;
pub const PA_XBOX_CLIENT_VERSION:      i32 = 206;

pub const ENC_NONCE_MACHINE_ACCOUNT: u32 = 1203;

pub const MACS_DOMAIN: &str = "MACS.XBOX.COM";
pub const MACS_REALM: &str = "MACS.XBOX.COM";

pub fn macs_sname() -> PrincipalName {
    PrincipalName {
        name_type: principal_names::NT_SRV_INST,
        name_string: vec![ "krbtgt".to_owned(), MACS_DOMAIN.to_owned() ],
    }
}

pub const AS_TGS_DOMAIN: &str = "XBOX.COM";
pub const AS_TGS_REALM: &str = "XBOX.COM";

pub fn as_tgs_sname() -> PrincipalName {
    PrincipalName {
        name_type: principal_names::NT_SRV_INST,
        name_string: vec![ "krbtgt".to_owned(), AS_TGS_DOMAIN.to_owned() ],
    }
}

pub fn gamertag_from_cname(cname: &PrincipalName, domains: &[&'static str]) -> Option<(String, &'static str)> {
    if cname.name_type != principal_names::NT_ENTERPRISE {
        return None;
    }

    if cname.name_string.len() != 1 {
        return None;
    }

    let mut name = cname.name_string[0].clone();

    let domain = domain_matches_name(&name, domains)?;

    for _ in 0..domain.len() {
        name.pop();
    }

    Some((name, domain))
}

fn domain_matches_name<'a>(name: &str, domains: &[&'a str]) -> Option<&'a str> {
    for domain in domains {
        if name.ends_with(domain) {
            return Some(domain)
        }
    }

    None
}