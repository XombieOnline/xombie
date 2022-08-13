<!-- cargo-sync-readme start -->

# Kerberos ASN1
This library defines the ASN1 structures used by the Kerberos
protocol as Rust structs. Based in the red_asn1 library.

Each type defined in this library provides a method `parse` to parse
an array of bytes and create the type, and a method `build` to create
an array of bytes from the type and its values.

## Examples

Decoding a string of Kerberos:
```rust
use kerberos_asn1::KerberosString;
use red_asn1::Asn1Object;

let raw_string = &[
                0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e,
                0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
            ];
let (rest_raw, kerberos_string) = KerberosString::parse(raw_string).unwrap();

assert_eq!("KINGDOM.HEARTS", kerberos_string);  
```
## References
- [RFC 4120, The Kerberos Network Authentication Service (V5)](https://tools.ietf.org/html/rfc4120)
- [RFC 6806, Kerberos Principal Name Canonicalization and Cross-Realm Referrals](https://tools.ietf.org/html/rfc6806)
- [MS-KILE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-KILE/2a32282e-dd48-4ad9-a542-609804b02cc9)


<!-- cargo-sync-readme end -->
