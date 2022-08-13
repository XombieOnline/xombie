use serde::{Deserialize, Serialize};

use std::io;
use std::fs;
use std::path::Path;

use xbox_sys::crypto::SymmetricKey;
use xbox_sys::account::{Gamertag, Domain, PassCode, Realm, UnsignedAccount, Xuid};

#[derive(Debug, Deserialize, Serialize)]
struct TomlAccount {
    xuid: [u8;8],
    gamertag: String,
    domain: String,
    realm: String,
    key: [u8;16],
}

#[derive(Debug)]
pub enum ReadTomlAccountError {
	Io(io::Error),
	ParseFile(toml::de::Error),
	ParseField(&'static str),
}

pub fn read_toml_account_file<P: AsRef<Path>>(path: P) -> Result<UnsignedAccount, ReadTomlAccountError> {
	use ReadTomlAccountError::*;

	let s = fs::read_to_string(path)
		.map_err(|err| Io(err))?;

	let toml_account: TomlAccount = toml::from_str(&s)
		.map_err(|err| ParseFile(err))?;
	
	let xuid = Xuid(u64::from_be_bytes(toml_account.xuid));
	
	Ok(UnsignedAccount {
		xuid,
		user_flags: 0,
		gamertag: Gamertag::try_from(toml_account.gamertag.as_str())
			.map_err(|_| ParseField("gamertag"))?,
		user_options: 0,
		passcode: PassCode::default(),
		domain: Domain::try_from(toml_account.domain.as_str())
			.map_err(|_| ParseField("domain"))?,
		kerberos_realm: Realm::try_from(toml_account.realm.as_str())
			.map_err(|_| ParseField("kerberos_realm"))?,
		key: SymmetricKey(toml_account.key),
	})
}
