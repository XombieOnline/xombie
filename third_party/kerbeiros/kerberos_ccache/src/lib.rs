//! Types used to store Kerberos credentials in a ccache
//!
//! # Example
//! Load and save into a file:
//! ```no_run
//! use kerberos_ccache::CCache;
//! use std::fs;
//!
//! let data = fs::read("./bob_tgt.ccache").expect("Unable to read file");
//!
//! let ccache = CCache::parse(&data)
//!     .expect("Unable to parse file content")
//!     .1;
//!
//! let data_2 = ccache.build();
//! fs::write("./bob_tgt2.ccache", data_2).expect("Unable to write file");
//! ```
//! # References
//! * [ccache definition](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html)
//! * [ccache types definition](https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt)
//! * [keytab definition](https://web.mit.edu/kerberos/www/krb5-latest/doc/formats/keytab_file_format.html)
//! * [keytab types definition](https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/keytab.txt)
//!
//!

mod header;
pub use header::*;

mod counted_octet_string;
pub use counted_octet_string::*;

mod principal;
pub use principal::*;

mod key_block;
pub use key_block::*;

mod times;
pub use times::*;

mod address;
pub use address::*;

mod auth_data;
pub use auth_data::*;

mod credential;
pub use credential::*;

mod ccache;
pub use ccache::*;

pub use nom::Err as Error;
pub use nom::IResult as Result;

pub mod mappers;

mod error;
pub use error::{ConvertResult, ConvertError};

