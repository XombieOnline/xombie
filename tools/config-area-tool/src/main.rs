use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write, self};
use std::path::Path;

use clap::{Args, Parser, Subcommand};

use xblive::crypto::primitives::{TripleDesKey, sha1_hmac, TRIPLE_DES_KEY_LEN, tdes_cbc_decrypt_in_place, BlockCryptError, tdes_cbc_encrypt_in_place};

use xbox_sys::account::{StoredAccount, UnsignedAccount, SIGNATURE_LEN};
use xbox_sys::codec::Decode;
use xbox_sys::config_area::{Sector, SECTOR_LEN, MAX_USERS_IN_TABLE, USER_TABLE_SECTOR, validate_sector, parse_user_table, FIRST_USER_SECTOR};
use xbox_sys::crypto::{SYMMETRIC_KEY_LEN, DesIv, SymmetricKey, keys::*};

use xombie::account::read_toml_account_file;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ImportMUAccount(ImportMUAccount),
    ImportAccountToml(ImportAccountToml),
}

#[derive(Args)]
struct ImportMUAccount {
    account_file: String,
}

#[derive(Args)]
struct ImportAccountToml {
    toml_path: String,
    config_partition_path: String,
    hd_key: String,
}

fn main() {
    let cli = Cli::parse();

    use Commands::*;
    match &cli.command {
        ImportMUAccount(args) => import_mu_account(args).unwrap(),
        ImportAccountToml(args) => import_account_toml(args).unwrap(),
    }
}

fn read_complete_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![];
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn import_mu_account(args: &ImportMUAccount) -> io::Result<()> {
    let file = read_complete_file(&args.account_file)?;

    let account = verify_decrypt_and_parse_account(&file, &AccountKeys::MU).unwrap();

    todo!("{:02x?}", account)
}

#[derive(Debug)]
enum VerifyAndParseAccountError {
    WrongSize(usize),
    KeyDecryption(BlockCryptError),
    SignatureCheckFailed,
    ParseError,
}

struct AccountKeys {
    iv: DesIv,
    des_seed: SymmetricKey,
    signature_key: SymmetricKey,
}

impl AccountKeys {
    const MU: AccountKeys = AccountKeys {
        iv: MU_USER_ACCOUNT_IV,
        des_seed: MU_USER_ACCOUNT_DES_SEED,
        signature_key: MU_USER_ACCOUNT_SIGNATURE_KEY,
    };

    fn from_hd_key_and_iv(hd_key: SymmetricKey, iv: DesIv) -> Self {
        AccountKeys {
            iv,
            des_seed: hd_key,
            signature_key: hd_key,
        }
    }

    fn gen_des_key(&self) -> TripleDesKey {
        let seed_0 = sha1_hmac(&USER_ACCOUNT_DES_SEED_KEY_0.0, &[&self.des_seed.0]);
        let seed_1 = sha1_hmac(&USER_ACCOUNT_DES_SEED_KEY_1.0, &[&self.des_seed.0]);

        let mut with_invalid_parity = [0u8;TRIPLE_DES_KEY_LEN];

        with_invalid_parity[0..4].copy_from_slice(&seed_0.0[0..4]);
        with_invalid_parity[4..].copy_from_slice(&seed_1.0);

        TripleDesKey::from_buf_with_invalid_parity(&with_invalid_parity)
    }

    fn sign_account(&self, account: UnsignedAccount, signature_time: u32) -> [u8;108] {
        let mut bytes = [0u8;108];

        let des_key = self.gen_des_key();

        let xuid_bytes = account.xuid.0.to_le_bytes();
        let user_flags_bytes = account.user_flags.to_le_bytes();
        let user_options_bytes = account.user_options.to_le_bytes();
        let signature_time_bytes = signature_time.to_le_bytes();

        let digest = sha1_hmac(&self.signature_key.0, &[
            &xuid_bytes,
            &user_flags_bytes,
            account.gamertag.bytes(),
            &user_options_bytes,
            &account.passcode.0,
            account.domain.bytes(),
            account.kerberos_realm.bytes(),
            &account.key.0,
            &signature_time_bytes,
        ]);

        let signature_bytes: [u8;SIGNATURE_LEN] = (&digest.0[..SIGNATURE_LEN]).try_into().unwrap();

        let mut encrypted_key = account.key.0;
        tdes_cbc_encrypt_in_place(&des_key, self.iv, &mut encrypted_key).unwrap();

        bytes[0..8].copy_from_slice(&xuid_bytes);
        bytes[8..12].copy_from_slice(&user_flags_bytes);
        bytes[12..28].copy_from_slice(account.gamertag.bytes());
        bytes[28..32].copy_from_slice(&user_options_bytes);
        bytes[32..36].copy_from_slice(&account.passcode.0);
        bytes[36..56].copy_from_slice(account.domain.bytes());
        bytes[56..80].copy_from_slice(account.kerberos_realm.bytes());
        bytes[80..96].copy_from_slice(&encrypted_key);
        bytes[96..100].copy_from_slice(&signature_time_bytes);
        bytes[100..108].copy_from_slice(&signature_bytes);

        bytes
    }
}

fn verify_decrypt_and_parse_account(input: &[u8], keys: &AccountKeys) -> Result<UnsignedAccount, VerifyAndParseAccountError> {
    if input.len() != std::mem::size_of::<StoredAccount>() {
        return Err(VerifyAndParseAccountError::WrongSize(input.len()))
    }

    let mut input: [u8;108] = input.try_into().unwrap();

    let des_key = keys.gen_des_key();

    let key_base = 80;
    let key_end = key_base + SYMMETRIC_KEY_LEN;

    {
        let buf = &mut input[key_base..key_end];
        tdes_cbc_decrypt_in_place(&des_key, keys.iv, buf)
            .map_err(|err| VerifyAndParseAccountError::KeyDecryption(err))?
    }

    {
        let signature_region = &input[..100];

        let digest = sha1_hmac(&keys.signature_key.0, &[signature_region]);

        if digest.0[0..8] != input[100..] {
            return Err(VerifyAndParseAccountError::SignatureCheckFailed)
        }
    }

    let (_, account) = UnsignedAccount::decode(&input)
        .map_err(|_| VerifyAndParseAccountError::ParseError)?;

    Ok(account)
}

fn import_account_toml(args: &ImportAccountToml) -> Result<(), ()> {
    let hd_key = SymmetricKey::parse_str(&args.hd_key).unwrap();
    let iv = DesIv(rand::random());
    let signature_time = 0x02987048;
    let account = read_toml_account_file(&args.toml_path).unwrap();

    let mut config_partition = BlockDevice::open(&args.config_partition_path).unwrap();

    let mut user_table = OnDiskUsers::read_from_block_device(&mut config_partition).unwrap();

    let sector_num = user_table.insert(account, iv).unwrap();

    let keys = AccountKeys::from_hd_key_and_iv(hd_key, iv);

    let encrypted_and_signed_account = keys.sign_account(account, signature_time);

    let account_sector = Sector::try_from(encrypted_and_signed_account.as_slice()).unwrap();

    let table_sector = Sector::try_from(user_table.encode().as_slice()).unwrap();

    config_partition.write_sector(sector_num, &account_sector).unwrap();

    config_partition.write_sector(USER_TABLE_SECTOR, &table_sector).unwrap();    

    Ok(())
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
enum Account {
    Valid(UnsignedAccount),
    Unchecked([u8;108]),
}

#[derive(Debug)]
struct OnDiskUsers {
    users: [Option<(DesIv, Account)>;MAX_USERS_IN_TABLE],
}

pub const USER_TABLE_ENCODED_BYTES: usize = 12 * MAX_USERS_IN_TABLE;

impl OnDiskUsers {
    fn read_from_block_device(config_partition: &mut BlockDevice) -> io::Result<Self> {
        let table_sector = config_partition.read_sector(USER_TABLE_SECTOR)?;

        let user_table = match validate_sector(&table_sector) {
            None => return Ok(OnDiskUsers::default()),
            Some(payload) => {
                match parse_user_table(payload) {
                    Ok((_, user_table)) => user_table,
                    Err(_) => return Ok(OnDiskUsers::default())
                }
            }
        };

        todo!("user_table: {:?}", user_table)
    }

    fn insert(&mut self, account: UnsignedAccount, iv: DesIv) -> Option<u64> {
        for (i, user) in self.users.iter_mut().enumerate() {
            if user.is_none() {
                *user = Some((iv, Account::Valid(account)));
                let sector_num = FIRST_USER_SECTOR + i as u64;
                return Some(sector_num)
            }
        }

        None
    }

    fn encode(&self) -> [u8;USER_TABLE_ENCODED_BYTES] {
        let mut encoded = [0u8;USER_TABLE_ENCODED_BYTES];

        for (i, user) in self.users.iter().enumerate() {
            if let Some((iv, _)) = user {
                let base = 12 * i;
                let end = i + 12;
                let bytes = &mut encoded[base..end];

                bytes[0..4].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
                bytes[4..12].copy_from_slice(&iv.0);
            }
        }

        encoded
    }
}

impl Default for OnDiskUsers {
    fn default() -> Self {
        OnDiskUsers {
            users: [None;MAX_USERS_IN_TABLE],
        }
    }
}

struct BlockDevice {
    f: File,
}

impl BlockDevice {
    fn open<P: AsRef<Path>>(path: P) -> io::Result<BlockDevice> {
        Ok(BlockDevice {
            f: OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?,
        })
    }

    fn read_sector(&mut self, sector: u64) -> io::Result<Sector> {
        let mut sector_buf = Sector::default();

        self.seek_to_sector(sector)?;
        self.f.read_exact(&mut sector_buf.0)?;

        Ok(sector_buf)
    }

    fn write_sector(&mut self, sector_num: u64, sector: &Sector) -> io::Result<()> {
        println!("write_sector: {}", sector_num);
        println!("sector: {:02x?}", sector.0);
        println!("{:02x?}", sector);
        self.seek_to_sector(sector_num)?;

        self.f.write_all(&sector.0)?;

        Ok(())
    }

    fn seek_to_sector(&mut self, sector: u64) -> io::Result<()> {
        let byte_offset = sector * (SECTOR_LEN as u64);
        self.f.seek(SeekFrom::Start(byte_offset))?;

        Ok(())
    }
}