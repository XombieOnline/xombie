use block_device::BlockDevice;
use clap::{Args, ArgEnum, Parser, Subcommand};
use xdvd::fs::{VolumeDescriptor, NO_CHILD};

use std::io;
use std::mem::size_of;
use std::sync::{Arc, Mutex};

type FileBlockDevice = block_device::file::FileBlockDevice::<{xdvd::SECTOR_LEN}>;
type PartitionBlockDevice = block_device::partition::PartitionBlockDevice::<{xdvd::SECTOR_LEN}>;

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
}

#[derive(Args, Debug)]
struct Info {
    #[clap(arg_enum)]
    kind: BlockDeviceKind,

    file: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
enum BlockDeviceKind {
    RawRedump,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Info(info) => do_info(info).unwrap(),
    }
}

fn do_info(info: &Info) -> io::Result<()> {
    let raw_block_device = FileBlockDevice::open(&info.file)?;

    let mut block_device = PartitionBlockDevice::new(
        Arc::new(Mutex::new(raw_block_device)),
        xdvd::redump::DATA_PARTITION_START_SECTOR,
        None);

    let volume_descriptor_block = block_device.read_block(xdvd::fs::VOLUME_DESCRIPTOR_SECTOR_NUMBER).unwrap();

    let (_, volume_descriptor) = VolumeDescriptor::parse(&volume_descriptor_block).unwrap();

    let root_directory_block = block_device.read_block(volume_descriptor.root_directory_sector as u64).unwrap();

    let root_dir_table = parse_table(&root_directory_block, 0);

    todo!("{:#x?}", root_dir_table)
}

#[allow(dead_code)]
#[derive(Debug)]
struct DirEntry {
    left: Option<Box<DirEntry>>,
    right: Option<Box<DirEntry>>,
    sector: u32,
    file_size: u32,
    attributes: u8,
    name: String,
}

fn parse_table(directory_table: &[u8], offset: u16) -> DirEntry {
    let offset = offset as usize * size_of::<u32>();

    println!("offset: {}", offset);

    let (_, raw_dir_entry) = xdvd::fs::DirEntry::parse(&directory_table[offset..]).unwrap();

    let right = if raw_dir_entry.left != NO_CHILD {
        Some(Box::new(parse_table(directory_table, raw_dir_entry.left)))
    } else {
        None
    };

    let left = if raw_dir_entry.right != NO_CHILD {
        Some(Box::new(parse_table(directory_table, raw_dir_entry.right)))
    } else {
        None
    };

    DirEntry {
        left,
        right,
        sector: raw_dir_entry.sector,
        file_size: raw_dir_entry.file_size,
        attributes: raw_dir_entry.attributes,
        name: String::from_utf8(raw_dir_entry.name.to_vec()).unwrap(),
    }
}