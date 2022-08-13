use chrono::{DateTime, TimeZone, Utc};
use kerberos_asn1::{Asn1Object, EncryptedData, EncryptionKey, Int32, KerberosTime, KrbError, PaData, PrincipalName, Realm};
use kerberos_constants::*;

use std::convert::TryInto;

use xblive::crypto::primitives::{Rc4HmacDecryptError, rc4_md5_hmac_decrypt, rc4_md5_hmac_encrypt};

use xbox_sys::crypto::{SymmetricKey, SYMMETRIC_KEY_LEN};

pub const UDP_PORT: u16 = 88;

pub const AD_TYPE_SERVICE_ADDRESSES: i32 = 10000;
pub const AD_TYPE_USERS:             i32 = 10001;

pub const USER_AT_DOMAIN: &str = "@xombie.org";

pub const AT_DOMAINS: &[&'static str] = &[
    USER_AT_DOMAIN,
    xblive::user::AT_DOMAIN,
];

#[derive(Debug, PartialEq)]
pub enum SymmetricKeyCreateError {
    UnknownAlgorithm,
    IncorrectLength(usize),
}

pub fn enc_key_to_symmetric_key(enc_key: &EncryptionKey) -> Result<SymmetricKey, SymmetricKeyCreateError> {
    if enc_key.keytype != etypes::RC4_HMAC {
        return Err(SymmetricKeyCreateError::UnknownAlgorithm)
    }

    let len = enc_key.keyvalue.len();

    let array: [u8;SYMMETRIC_KEY_LEN] = enc_key.keyvalue.clone()
        .try_into()
        .map_err(|_| SymmetricKeyCreateError::IncorrectLength(len))?;

    Ok(SymmetricKey(array))
}

pub fn krb_encode_and_encrypt<T>(asn_obj: T, key: &[u8], nonce: u32, kvno: Option<u32>) -> EncryptedData
where
    T: Asn1Object
{
    let plaintext = asn_obj.build();

    krb_rc4_hmac_md5(&plaintext, key, nonce, kvno)
}

pub fn krb_rc4_hmac_md5(plaintext: &[u8], key: &[u8], nonce: u32, kvno: Option<u32>) -> EncryptedData {
    EncryptedData {
        etype: etypes::RC4_HMAC,
        kvno,
        cipher: rc4_md5_hmac_encrypt(key, nonce, plaintext),
    }
}

#[derive(Debug)]
pub enum DecryptError {
    UnknownEType(Int32),
    Decrypting(Rc4HmacDecryptError),
    Decode(kerberos_asn1::Error),
}

pub fn krb_decrypt(encrypted: &EncryptedData, key: SymmetricKey, nonce: u32) -> Result<Vec<u8>, DecryptError> {
    match encrypted.etype {
        etypes::RC4_HMAC => {
            rc4_md5_hmac_decrypt(&key.0, nonce, &encrypted.cipher)
                .map_err(|err| DecryptError::Decrypting(err))
        }
        _ => Err(DecryptError::UnknownEType(encrypted.etype)),
    }
}

pub fn krb_decrypt_and_decode<T>(encrypted: &EncryptedData, key: SymmetricKey, nonce: u32) -> Result<T, DecryptError>
where
    T: Asn1Object
{
    let plaintext = krb_decrypt(encrypted, key, nonce)?;

    let (_, asn1_obj) = T::parse(&plaintext)
        .map_err(|err| DecryptError::Decode(err))?;

    Ok(asn1_obj)
}

pub fn krb_error(
    error_code: Int32,
    ctime: Option<KerberosTime>,
    stime: KerberosTime,
    crealm: Option<Realm>,
    cname: Option<PrincipalName>,
    realm: Realm,
    sname: PrincipalName,
) -> KrbError {
    KrbError {
        pvno: protocol_version::PVNO,
        msg_type: message_types::KRB_ERROR,
        ctime: ctime,
        cusec: None,
        stime: stime,
        susec: 0,
        error_code,
        crealm,
        cname,
        realm,
        sname,
        e_text: None,
        e_data: None,
    }
}

/// Midnight, Jan 1, 1970
/// Useful for expiration of obviously invalid tickets
pub fn unix_epoch() -> KerberosTime {
    from_utc(Utc.ymd(1970, 1, 1).and_hms(0, 0, 0))
}

/// Sample current time
pub fn now() -> KerberosTime {
    from_utc(Utc::now())
}

/// Wrap a arbitrary DateTime<Utc> in a Kerberos
pub fn from_utc(time: DateTime<Utc>) -> KerberosTime {
    KerberosTime {
        time: red_asn1::GeneralizedTime {
            time,
        }
    }
}

/// Find the padata with the given padata_type in an array.  Return None
/// if multiple padatas have that type
pub fn find_unique_padata<'a>(padata_type: i32, v: &'a Option<Vec<PaData>>) -> Option<&'a PaData> {
    let v = match v {
        None => return None,
        Some(ref v) => v,
    };

    let mut last_off = None;

    let count = v.iter().enumerate().fold(0, 
        |acc, (i, padata)| 
            if padata.padata_type == padata_type {
                last_off = Some(i);
                acc + 1
            } else {
                acc
            });
    if count == 1 {
        last_off.map(|i| &v[i])
    } else {
        None
    }
}

