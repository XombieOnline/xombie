use super::KerberosString;

/// (*Realm*) Kerberos realm.
/// ```asn1
/// Realm           ::= KerberosString
/// ```
pub type Realm = KerberosString;
