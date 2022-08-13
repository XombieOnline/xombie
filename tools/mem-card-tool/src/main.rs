#![allow(dead_code)]

use block_device::BlockDevice;

use block_device::usb::UsbMassStorageBlockDeviceOpenError;
use clap::{Args, Parser, Subcommand};

use rusb::{Device, DeviceDescriptor, DeviceHandle, UsbContext};
use xblive::crypto::primitives::{TripleDesKey, sha1_hmac, TRIPLE_DES_KEY_LEN, tdes_cbc_encrypt_in_place};
use xbox_sys::account::{UnsignedAccount, SIGNATURE_LEN};
use xbox_sys::crypto::keys::*;
use xbox_sys::crypto::{DesIv, SymmetricKey};

use std::io;
use std::time::Duration;

use xbox_sys::codec::{Decode, BufPut};
use xbox_sys::fatx::{VOLUME_HEADER_BASE_BLOCK, VOLUME_HEADER_NUM_BLOCKS, VolumeHeader, SECTOR_SIZE};

use xombie::account::{ReadTomlAccountError, read_toml_account_file};

const BLOCK_LENGTH: usize = 512;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Info(Info),
    ImportAccountToml(ImportAccountToml),
    Dump(Dump),
}

#[derive(Args)]
struct Info {
    vendor_id: String,
    product_id: String,
}

#[derive(Args)]
struct ImportAccountToml {
    toml_path: String,
    #[clap(subcommand)]
    mu_device: BlockDeviceArgs,
}

#[derive(Args)]
struct Dump {
    output_path: String,
    #[clap(subcommand)]
    mu_device: BlockDeviceArgs,
}

#[derive(Subcommand)]
enum BlockDeviceArgs {
    Raw{ path: String },
    Usb{ vid: String, pid: String },
}

fn main() {
    let cli = Cli::parse();

    use Commands::*;
    match &cli.command {
        Info(args) => info(args).unwrap(),
        ImportAccountToml(args) => import_account_toml(args).unwrap(),
        Dump(args) => dump(args).unwrap(),
    }
}

#[derive(Debug)]
enum InfoError {
    VendorIdParseError,
    ProductIdParseError,
    CannotCreateUsbContext(rusb::Error),
    CannotCreateDevice(MemcardDeviceOpenError)
}

fn info(args: &Info) -> Result<(), InfoError> {
    let vid = id_from_hex(&args.vendor_id)
        .ok_or(InfoError::VendorIdParseError)?;

    let pid = id_from_hex(&args.product_id)
        .ok_or(InfoError::ProductIdParseError)?;

    let mut ctx = rusb::Context::new()
        .map_err(|err| InfoError::CannotCreateUsbContext(err))?;

    let mut memcard = MemcardDevice::open(vid, pid, &mut ctx)
        .map_err(|err| InfoError::CannotCreateDevice(err))?;

    // let inquiry_command = ScsiInquiryCommand::new(0, 0);

    // let (inquiry_resp, csw) = memcard.command::<_, ScsiInquiryResponse>(&inquiry_command).unwrap();

    // println!("{:02x?} {:02x?}", inquiry_resp, csw);

    let read_capacity_command = ScsiReadCapacity10Command::new();

    let (read_capacity_resp, csw) = memcard.command::<_, ScsiReadCapacity10Response>(&read_capacity_command).unwrap();

    println!("{:02x?} {:02x?}", read_capacity_resp, csw);

    let read_superblock_command = ScsiRead10Command::new(0);

    let (superblock, csw) = memcard.command::<_, ScsiSector>(&read_superblock_command).unwrap();

    todo!("{:02x?} {:02x?}", superblock, csw);
}

#[derive(Debug)]
enum MemcardDeviceOpenError {
    UnableToOpenDevice,
    TooManyDeviceConfigurations(u8),
    UnableToReadConfigDescriptor(rusb::Error),
    TooManyInterfaces(usize),
    TooManyInterfaceDescriptors(usize),
    WrongNumberOfEndpoints(usize),
    SetActiveConfiguration(rusb::Error),
    ClaimInterface(rusb::Error),
    SetAlternateSetting(rusb::Error),
}

#[derive(Debug)]
enum MemcardSendCommandError {
    SendCommandBlock(rusb::Error),
    ReceiveResponse(rusb::Error),
    ReadingStatus(rusb::Error),
}

#[allow(dead_code)]
struct MemcardDevice<T: UsbContext> {
    device: Device<T>,
    device_desc: DeviceDescriptor,
    handle: DeviceHandle<T>,
    config: u8,
    iface: u8,
    setting: u8,
    in_address: u8,
    out_address: u8,

    tag: u32,
}

impl<T: UsbContext> MemcardDevice<T> {
    fn open(vid: u16, pid: u16, ctx: &mut T) -> Result<MemcardDevice<T>, MemcardDeviceOpenError> {
        let (device, device_desc, mut handle) = open_device(ctx, vid, pid)
            .ok_or(MemcardDeviceOpenError::UnableToOpenDevice)?;

        if device_desc.num_configurations() != 1 {
            return Err(MemcardDeviceOpenError::TooManyDeviceConfigurations(
                device_desc.num_configurations()
            ))
        }

        let config_desc = device.config_descriptor(0)
            .map_err(|err| MemcardDeviceOpenError::UnableToReadConfigDescriptor(err))?;

        let interfaces: Vec<_> = config_desc.interfaces().collect();

        if interfaces.len() != 1 {
            return Err(MemcardDeviceOpenError::TooManyInterfaces(interfaces.len()))
        }

        let interface_descriptors: Vec<_> = interfaces[0].descriptors().collect();

        if interface_descriptors.len() != 1 {
            return Err(MemcardDeviceOpenError::TooManyInterfaceDescriptors(
                interface_descriptors.len()
            ))
        }

        let endpoints: Vec<_> = interface_descriptors[0].endpoint_descriptors().collect();

        if endpoints.len() != 2 {
            return Err(MemcardDeviceOpenError::WrongNumberOfEndpoints(endpoints.len()))
        }

        let in_desc = &endpoints[0];
        let out_desc = &endpoints[1];

        let config = config_desc.number();
        let iface = interface_descriptors[0].interface_number();
        let setting = interface_descriptors[0].setting_number();

        handle.set_active_configuration(config)
            .map_err(|err| MemcardDeviceOpenError::SetActiveConfiguration(err))?;

        handle.claim_interface(iface)
            .map_err(|err| MemcardDeviceOpenError::ClaimInterface(err))?;

        handle.set_alternate_setting(iface, setting)
            .map_err(|err| MemcardDeviceOpenError::SetAlternateSetting(err))?;

        Ok(MemcardDevice {
            device,
            device_desc,
            handle,
            config: config_desc.number(),
            iface: interface_descriptors[0].interface_number(),
            setting: interface_descriptors[0].setting_number(),
            in_address: in_desc.address(),
            out_address: out_desc.address(),

            tag: 0x69000420,
        })
    }

    fn consume_tag(&mut self) -> u32 {
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1);
        tag
    }

    fn command<Cmd: ScsiCommand, Resp: ScsiResp>(&mut self, cmd: &Cmd) -> Result<(Resp, CommandStatusWrapper), MemcardSendCommandError> {
        let tag = self.consume_tag();

        let command_block = CommandBlockWrapper::new(cmd, tag);

        let _ = self.handle.write_bulk(
            self.out_address,
            &command_block.0,
            Duration::from_secs(1))
            .map_err(|err| MemcardSendCommandError::SendCommandBlock(err))?;

        let resp = if cmd.is_data_in() {
            let mut buf = [0u8;512];

            let buf = &mut buf[..Resp::max_len()];
    
            let len_recevied = self.handle.read_bulk(
                self.in_address,
                buf,
                Duration::from_secs(1))
                .map_err(|err| MemcardSendCommandError::ReceiveResponse(err))?;

            println!("RX: {} {:02x?}", len_recevied, buf);

            Resp::from_bytes(buf).unwrap()
        } else {
            todo!()
        };

        let mut csw = CommandStatusWrapper::new();

        let _ = self.handle.read_bulk(
            self.in_address,
            &mut csw.0,
            Duration::from_secs(1))
            .map_err(|err| MemcardSendCommandError::ReadingStatus(err))?;

        Ok((resp, csw))
    }
}

fn open_device<T: UsbContext>(
    ctx: &mut T,
    vid: u16,
    pid: u16,
) -> Option<(Device<T>, DeviceDescriptor, DeviceHandle<T>)> {
    let devices = match ctx.devices() {
        Ok(d) => d,
        Err(_) => return None,
    };

    for device in devices.iter() {
        let device_desc = match device.device_descriptor() {
            Ok(d) => d,
            Err(_) => continue,
        };

        if device_desc.vendor_id() == vid && device_desc.product_id() == pid {
            match device.open() {
                Ok(handle) => return Some((device, device_desc, handle)),
                Err(_) => continue,
            }
        }
    }

    None
}


fn id_from_hex(s: &str) -> Option<u16> {
    let mut out = [0u8;2];
    hex::decode_to_slice(s, &mut out).ok()?;

    Some(u16::from_be_bytes(out))
}

trait ScsiCommand {
    type Response: ScsiResp;

    fn bytes<'a>(&'a self) -> &'a[u8];
    fn is_data_in(&self) -> bool;
}

const SCSI_CONTROL: u8 = 0x00;

const SCSI_OP_INQUIRY:          u8 = 0x12;
const SCSI_OP_READ_CAPACITY_10: u8 = 0x25;
const SCSI_OP_READ_10:          u8 = 0x28;

struct ScsiInquiryCommand {
    bytes: [u8;6],    
}

impl ScsiInquiryCommand {
    fn new(lun_evpd: u8, page_code: u8) -> Self {
        ScsiInquiryCommand {
            bytes: [
                SCSI_OP_INQUIRY,
                lun_evpd,
                page_code,
                0,
                std::mem::size_of::<ScsiInquiryResponse>() as u8,
                SCSI_CONTROL,
            ]
        }
    }
}

impl ScsiCommand for ScsiInquiryCommand {
    type Response = ScsiInquiryResponse;

    fn bytes<'a>(&'a self) -> &'a[u8] {
        &self.bytes
    }

    fn is_data_in(&self) -> bool {
        true
    }
}

struct ScsiReadCapacity10Command {
    bytes: [u8;10],
}

impl ScsiReadCapacity10Command {
    fn new() -> Self {
        ScsiReadCapacity10Command {
            bytes: [
                SCSI_OP_READ_CAPACITY_10,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                SCSI_CONTROL,
            ]
        }
    }
}


impl ScsiCommand for ScsiReadCapacity10Command {
    type Response = ScsiReadCapacity10Response;

    fn bytes<'a>(&'a self) -> &'a[u8] {
        &self.bytes
    }

    fn is_data_in(&self) -> bool {
        true
    }
}


struct ScsiRead10Command {
    bytes: [u8;10],
}

impl ScsiRead10Command {
    fn new(lba: u32) -> Self {
        let lba_bytes = lba.to_be_bytes();
        ScsiRead10Command {
            bytes: [
                SCSI_OP_READ_10,
                0,
                lba_bytes[0],
                lba_bytes[1],
                lba_bytes[2],
                lba_bytes[3],
                0,
                0x00,
                0x01,
                SCSI_CONTROL,
            ]
        }
    }
}

impl ScsiCommand for ScsiRead10Command {
    type Response = ScsiSector;

    fn bytes<'a>(&'a self) -> &'a[u8] {
        &self.bytes
    }

    fn is_data_in(&self) -> bool {
        true
    }
}

trait ScsiResp: Sized {
    fn max_len() -> usize;

    fn from_bytes(buf: &[u8]) -> Option<Self>;
}

#[derive(Debug)]
struct ScsiInquiryResponse {
    bytes: [u8;36],
}

impl ScsiResp for ScsiInquiryResponse {
    fn max_len() -> usize {
        36
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        Some(ScsiInquiryResponse{
            bytes: buf.try_into().unwrap()
        })
    }
}

#[derive(Debug)]
struct ScsiReadCapacity10Response {
    bytes: [u8;8],
}

impl ScsiResp for ScsiReadCapacity10Response {
    fn max_len() -> usize {
        8
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        Some(ScsiReadCapacity10Response {
            bytes: buf.try_into().unwrap()
        })
    }
}

#[derive(Debug)]
struct ScsiSector {
    bytes: [u8;512],
}

impl ScsiResp for ScsiSector {
    fn max_len() -> usize {
        512
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        Some(ScsiSector {
            bytes: buf.try_into().unwrap()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_from_hex() {
        assert_eq!(Some(0x69), id_from_hex("0069"));
        assert_eq!(Some(0x1420), id_from_hex("1420"));
        assert_eq!(None, id_from_hex("420"));
    }
}

struct CommandBlockWrapper([u8;31]);

impl CommandBlockWrapper {
    fn new<Cmd: ScsiCommand>(cmd: &Cmd, tag: u32) -> CommandBlockWrapper {
        let tag_bytes = tag.to_le_bytes();
        let data_transfer_len = Cmd::Response::max_len() as u32;
        let data_transfer_len_bytes = data_transfer_len.to_le_bytes();

        let mut bytes = [0u8;31];

        bytes[0..4].copy_from_slice(&[0x55, 0x53, 0x42, 0x43]);
        bytes[4..8].copy_from_slice(&tag_bytes);
        bytes[8..12].copy_from_slice(&data_transfer_len_bytes);
        bytes[12] = if cmd.is_data_in() {
            0x80
        } else {
            0
        };
        bytes[13] = 0; // lun 0

        let cmd_bytes = cmd.bytes();
        bytes[14] = (cmd_bytes.len() as u8) << 3;

        let cbwcb_base = 15;
        let cbwcb_end = cbwcb_base + cmd_bytes.len();

        bytes[cbwcb_base..cbwcb_end].copy_from_slice(cmd_bytes);

        CommandBlockWrapper(bytes)
    }
}

#[derive(Debug)]
struct CommandStatusWrapper([u8;13]);

impl CommandStatusWrapper {
    fn new() -> Self {
        CommandStatusWrapper([0u8;13])
    }
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

#[derive(Debug)]
enum OpenBlockDeviceError {
    Io(io::Error),
    UsbError(UsbMassStorageBlockDeviceOpenError),
} 

fn open_block_device(args: &BlockDeviceArgs) -> Result<Box<dyn BlockDevice<BLOCK_LENGTH>>, OpenBlockDeviceError> {
    use OpenBlockDeviceError::*;

    let device: Box<dyn BlockDevice<BLOCK_LENGTH>> = match args {
        BlockDeviceArgs::Raw { path } =>
            Box::new(block_device::file::FileBlockDevice::open(path)
                .map_err(|err| Io(err))?),
        BlockDeviceArgs::Usb { vid, pid } =>
            Box::new(block_device::usb::UsbMassStorageBlockDevice::open(vid.as_str(), pid.as_str())
                .map_err(|err| UsbError(err))?),
    };

    Ok(device)
}

#[derive(Debug)]
enum ImportAccountTomlError {
    CouldNotReadToml(ReadTomlAccountError),
    CouldNotOpenDevice(OpenBlockDeviceError),
    CouldNotReadVolumeHeader(std::io::Error),
    CouldNotWriteVolumeHeader(std::io::Error),
}

fn import_account_toml(args: &ImportAccountToml) -> Result<(), ImportAccountTomlError> {
    use ImportAccountTomlError::*;

    let account = read_toml_account_file(&args.toml_path)
        .map_err(|err| CouldNotReadToml(err))?;

    let mut device = open_block_device(&args.mu_device)
        .map_err(|err| CouldNotOpenDevice(err))?;

    let buf = device.read_sequence_to_vec(VOLUME_HEADER_BASE_BLOCK, VOLUME_HEADER_NUM_BLOCKS)
        .map_err(|err| CouldNotReadVolumeHeader(err))?;

    let (_, mut volume_header) = VolumeHeader::decode(&buf).unwrap();

    volume_header.mu_online_account_buf = AccountKeys::MU.sign_account(account, 0x02987048);

    volume_header.volume_name = [0;16];

    for (i, c) in account.gamertag.bytes().iter().enumerate() {
        volume_header.volume_name[i] = *c as u16;

        if *c == b'\0' {
            break;
        }
    }

    let mut volume_header_buffer = vec![];

    volume_header.put(&mut volume_header_buffer);

    println!("{:02x?}", volume_header);
    println!("{:02x?}", volume_header_buffer);

    volume_header_buffer.truncate(SECTOR_SIZE);

    println!("{:02x?}", volume_header_buffer);

    device.write_sequence(&volume_header_buffer, VOLUME_HEADER_BASE_BLOCK)
        .map_err(|err| CouldNotWriteVolumeHeader(err))?;

    Ok(())
}

#[derive(Debug)]
enum DumpError {
    OutputFileOpenError(io::Error),
    CouldNotOpenDevice(OpenBlockDeviceError),
    CouldNotReadBlock(io::Error),
    WriteFile(io::Error),
}

fn dump(args: &Dump) -> Result<(), DumpError> {
    use io::Write;
    use DumpError::*;

    let mut file = std::fs::File::create(args.output_path.as_str())
        .map_err(|err| WriteFile(err))?;

    let mut device = open_block_device(&args.mu_device)
        .map_err(|err| CouldNotOpenDevice(err))?;

    for i in 0..device.num_blocks() {
        let block = device.read_block(i)
            .map_err(|err| CouldNotReadBlock(err))?;

        file.write(&block)
            .map_err(|err| WriteFile(err))?;
    }

    Ok(())
}