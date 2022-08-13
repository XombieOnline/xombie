//! Types used to store Kerberos credentials in a keytab
//!
//! # Example
//! Load and save into a file:
//! ```no_run
//! use kerberos_keytab::Keytab;
//! use std::fs;
//!
//! let data = fs::read("./user.keytab").expect("Unable to read file");
//!
//! let keytab = Keytab::parse(&data)
//!     .expect("Unable to parse file content")
//!     .1;
//!
//! let data_2 = keytab.build();
//! fs::write("./user2.keytab", data_2).expect("Unable to write file");
//! ```
//! # References
//! * [keytab definition](https://web.mit.edu/kerberos/www/krb5-latest/doc/formats/keytab_file_format.html)
//! * [keytab types definition](https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/keytab.txt)
//!
//!


mod counted_octet_string;
pub use counted_octet_string::CountedOctetString;

mod key_block;
pub use key_block::KeyBlock;

mod keytab_entry;
pub use keytab_entry::KeytabEntry;

mod keytab;
pub use keytab::Keytab;
