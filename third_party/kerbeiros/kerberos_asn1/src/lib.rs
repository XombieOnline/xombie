//! # Kerberos ASN1
//! This library defines the ASN1 structures used by the Kerberos
//! protocol as Rust structs. Based in the red_asn1 library.
//!
//! Each type defined in this library provides a method `parse` to parse
//! an array of bytes and create the type, and a method `build` to create
//! an array of bytes from the type and its values.
//!
//! ## Examples
//!
//! Decoding a string of Kerberos:
//! ```rust
//! use kerberos_asn1::KerberosString;
//! use red_asn1::Asn1Object;
//!
//! let raw_string = &[
//!                 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e,
//!                 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
//!             ];
//! let (rest_raw, kerberos_string) = KerberosString::parse(raw_string).unwrap();
//!
//! assert_eq!("KINGDOM.HEARTS", kerberos_string);  
//! ```
//! ## References
//! - [RFC 4120, The Kerberos Network Authentication Service (V5)](https://tools.ietf.org/html/rfc4120)
//! - [RFC 6806, Kerberos Principal Name Canonicalization and Cross-Realm Referrals](https://tools.ietf.org/html/rfc6806)
//! - [MS-KILE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-KILE/2a32282e-dd48-4ad9-a542-609804b02cc9)
//! - [MS-SFU](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)
//!

mod ap_options;
pub use ap_options::ApOptions;

mod ap_rep;
pub use ap_rep::ApRep;

mod ap_req;
pub use ap_req::ApReq;

mod authenticator;
pub use authenticator::Authenticator;

mod authorization_data;
pub use authorization_data::{AuthorizationData, AuthorizationDataEntry};

mod checksum;
pub use checksum::Checksum;

mod enc_ap_rep_part;
pub use enc_ap_rep_part::EncApRepPart;

mod enc_as_rep_part;
pub use enc_as_rep_part::EncAsRepPart;

mod enc_kdc_rep_part;
pub use enc_kdc_rep_part::EncKdcRepPart;

mod enc_krb_cred_part;
pub use enc_krb_cred_part::EncKrbCredPart;

mod enc_krb_priv_part;
pub use enc_krb_priv_part::EncKrbPrivPart;

mod enc_tgs_rep_part;
pub use enc_tgs_rep_part::EncTgsRepPart;

mod enc_ticket_part;
pub use enc_ticket_part::EncTicketPart;

mod kerb_ad_restriction_entry;
pub use kerb_ad_restriction_entry::KerbAdRestrictionEntry;

mod kerb_error_data;
pub use kerb_error_data::KerbErrorData;

mod kerb_key_list_rep;
pub use kerb_key_list_rep::KerbKeyListRep;

mod kerb_key_list_req;
pub use kerb_key_list_req::KerbKeyListReq;

mod kerb_local;
pub use kerb_local::KerbLocal;

mod krb_cred;
pub use krb_cred::KrbCred;

mod krb_cred_info;
pub use krb_cred_info::KrbCredInfo;

mod krb_priv;
pub use krb_priv::KrbPriv;

mod kdc_req;
pub use kdc_req::KdcReq;

mod krb_safe;
pub use krb_safe::KrbSafe;

mod krb_safe_body;
pub use krb_safe_body::KrbSafeBody;

mod tgs_rep;
pub use tgs_rep::TgsRep;

mod tgs_req;
pub use tgs_req::TgsReq;

mod transited_encoding;
pub use transited_encoding::TransitedEncoding;

mod typed_data;
pub use typed_data::{TypedData, TypedDataEntry};

mod int32;
pub use int32::Int32;

mod uint32;
pub use uint32::UInt32;

mod kerberos_string;
pub use kerberos_string::KerberosString;

mod microseconds;
pub use microseconds::{Microseconds, MAX_MICROSECONDS, MIN_MICROSECONDS};

mod kerberos_time;
pub use kerberos_time::KerberosTime;

mod kerberos_flags;
pub use kerberos_flags::KerberosFlags;

mod realm;
pub use realm::Realm;

mod principal_name;
pub use principal_name::PrincipalName;

mod host_address;
pub use host_address::{padd_netbios_string, HostAddress, HostAddresses};

mod pa_data;
pub use pa_data::{
    AdAndOr, AdIfRelevant, AdKdcIssued, AdMandatoryForKdc, EtypeInfo,
    EtypeInfo2, EtypeInfo2Entry, EtypeInfoEntry, KerbPaPacRequest, MethodData,
    PaData, PaEncTimestamp, PaEncTsEnc, PaForUser, PaPacOptions,
    PaSupportedEnctypes, S4uUserId, PaS4uX509User
};

mod encrypted_data;
pub use encrypted_data::EncryptedData;

mod encryption_key;
pub use encryption_key::EncryptionKey;

mod ticket;
pub use ticket::Ticket;

mod ticket_flags;
pub use ticket_flags::TicketFlags;

mod kdc_options;
pub use kdc_options::KdcOptions;

mod kdc_req_body;
pub use kdc_req_body::KdcReqBody;

mod as_req;
pub use as_req::AsReq;

mod as_rep;
pub use as_rep::AsRep;

mod last_req;
pub use last_req::{LastReq, LastReqEntry};

mod krb_error;
pub use krb_error::KrbError;

pub use red_asn1::Asn1Object;
pub use red_asn1::Error;
pub use red_asn1::Result;
pub use red_asn1::TagClass;
