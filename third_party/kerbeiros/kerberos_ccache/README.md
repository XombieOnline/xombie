<!-- cargo-sync-readme start -->

Types used to store Kerberos credentials in a ccache

# Example
Load and save into a file:
```no_run
use kerberos_ccache::CCache;
use std::fs;

let data = fs::read("./bob_tgt.ccache").expect("Unable to read file");

let ccache = CCache::parse(&data)
    .expect("Unable to parse file content")
    .1;

let data_2 = ccache.build();
fs::write("./bob_tgt2.ccache", data_2).expect("Unable to write file");
```
# References
* [ccache definition](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html)
* [ccache types definition](https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt)

<!-- cargo-sync-readme end -->
