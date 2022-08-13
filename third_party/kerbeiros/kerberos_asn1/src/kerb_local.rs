use red_asn1::OctetString;

/// (*KERB-LOCAL*) contain implementation-specific data used
/// when the Kerberos client and application server are on the same host.
/// Defined in MS-KILE, 2.2.4.
/// ```asn1
/// KERB-LOCAL ::= OCTET STRING --Implementation-specific data which MUST be
///                             --ignored if Kerberos client is not local.
/// ```
pub type KerbLocal = OctetString;
