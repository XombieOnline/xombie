<!-- cargo-sync-readme start -->

# Red ASN1
A little library to build/parse ASN1 DER

## Examples
Parsing and building `bool`:
```rust
use red_asn1::Asn1Object;

assert_eq!(true, bool::parse(&[0x1, 0x1, 0xff]).unwrap().1);
assert_eq!(false, bool::parse(&[0x1, 0x1, 0x0]).unwrap().1);

assert_eq!(true.build(), vec![0x1, 0x1, 0xff]);
assert_eq!(false.build(), vec![0x1, 0x1, 0x0]);
```


Parsing and building `Integer`:
```rust
use red_asn1::{Integer, Asn1Object};

assert_eq!(2, Integer::parse(&[0x2, 0x1, 0x2]).unwrap().1);
assert_eq!(2.build(), vec![0x2, 0x1, 0x2]);
```

Parsing and building `String`:
```rust
use red_asn1::Asn1Object;

assert_eq!(
    "John".to_string(), 
    String::parse(&[0x1b, 0x4, 0x4a, 0x6f, 0x68, 0x6e]).unwrap().1
);

assert_eq!(
    "John".to_string().build(), 
    vec![0x1b, 0x4, 0x4a, 0x6f, 0x68, 0x6e]
);
```


Creating custom sequences:

```rust
/*
Person ::= [APPLICATION 1] SEQUENCE {
    name:       [0] GeneralString,
    age:        [1] Integer,
    address:    [2] GeneralString OPTIONAL,
}
*/

use red_asn1::*;
use red_asn1_derive::Sequence;

#[derive(Sequence, Default)]
#[seq(application_tag = 1)]
struct Person {
    #[seq_field(context_tag = 0)]
    pub name: GeneralString,
    #[seq_field(context_tag = 1)]
    pub age: Integer,
    #[seq_field(context_tag = 2)]
    pub address: Option<GeneralString>
}

let john = Person{
    name: GeneralString::from("John").into(),
    age: Integer::from(18).into(),
    address: None
};

assert_eq!(
    vec![
        0x61, 0xf, 0x30, 0xd,
        0xa0, 0x6, 0x1b, 0x4, 0x4a, 0x6f, 0x68, 0x6e, // "John"
        0xa1, 0x3, 0x2, 0x1, 0x12 // 18
    ]
    , john.build()
);

let (_, rachel) = Person::parse(&[
    0x61, 0x1b, 0x30, 0x19,
    0xa0, 0x8, 0x1b, 0x6, 0x52, 0x61, 0x63, 0x68, 0x65, 0x6c, // "Rachel"
    0xa1, 0x3, 0x2, 0x1, 0x1e, // 30
    0xa2, 0x8, 0x1b, 0x6, 0x48, 0x61, 0x77, 0x61, 0x69, 0x69 // "Hawaii"
]).unwrap();

assert_eq!("Rachel", rachel.name);
assert_eq!(30, rachel.age);
assert_eq!(Some("Hawaii".to_string()), rachel.address);

```

## Implemented types

| ASN1            | red_asn1 type   | Rust type                                |
|-----------------|-----------------|------------------------------------------|
| BOOLEAN         | Boolean         | bool                                     |
| INTEGER         | Integer         | i128, i64, i32, i16, u32                 |
| BIT STRING      | BitSring        |                                          |
| OCTET STRING    | OctetString     | Vec\<u8\>                                |
| GeneralString   | GeneralString   | String                                   |
| IA5String       | IA5String       | ascii::AsciiString                       |
| GeneralizedTime | GeneralizedTime |                                          |
| SEQUENCE OF     | SequenceOf      | Vec<T: Asn1Object>                       |
| SEQUENCE        |                 | struct with #[derive(Sequence, Default)] |
| OPTIONAL        | Optional        | Option                                   |
|                 |                 |                                          |

<!-- cargo-sync-readme end -->
