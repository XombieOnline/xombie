use super::address::*;

/// Container that encapsules different types of preauthentication data structures.
/// # Definition
/// ```c
/// authdata {
///     uint16_t authtype;
///     counted_octet_string authdata;
/// };
/// ```
///
pub type AuthData = Address;
