use std::io::{self, Cursor};
use std::time::{UNIX_EPOCH, SystemTime};

use pcapng_writer::blocks::EnhancedPacketBlock;
use pcapng_writer::blocks::{options::Options, SectionHeaderBlock, InterfaceDescriptionBlock};
use pcapng_writer::enums::LinkType;
use pcapng_writer::utils::DEFAULT_TSRES;
use pcapng_writer::writer::Encodable;

use tokio::{fs::File, io::AsyncWriteExt};

use xblive::net::InAddr;
use xblive::sg::packet::Kind;

use crate::ip_conversion::IpConverter;

pub struct PcapngFile {
	path: String,
	file: File,
	ip_converter: IpConverter,
}

impl PcapngFile {
	pub async fn create_temp(client_addr: InAddr, server_addr: InAddr) -> io::Result<PcapngFile> {
		let num: u128 = rand::random();

		let path = format!("/tmp/translated-xombie-{:032x}.pcapng", num);

		let mut file = File::create(&path)
			.await?;

		write_header(&mut file).await?;

		Ok(PcapngFile {
			path,
			file,
			ip_converter: IpConverter::new(client_addr, server_addr),
		})
	}

	pub fn path(&self) -> String {
		self.path.clone()
	}

	pub async fn log<'a>(&mut self, payload: &[u8], kind: &'a Kind<'a>, from_client: bool) -> io::Result<()> {
		match kind {
			Kind::Control(_) => {}
			Kind::Tcp(sg_tcp_header) => {
				let buf = self.ip_converter.convert_sg_tcp_packet(sg_tcp_header, payload, from_client);

				let nanoseconds = SystemTime::now()
					.duration_since(UNIX_EPOCH)
					.unwrap()
					.as_nanos();

				let empty_options = Options::new();

				let epb = EnhancedPacketBlock::new_with_timestamp(
					0,
					DEFAULT_TSRES,
					nanoseconds,
					buf.len() as u32,
					buf.len() as u32,
					&buf,
					&empty_options);

				write_encodable(
					&epb,
					&mut self.file,
				).await?;
			}
		}

		Ok(())
	}
}

async fn write_header(file: &mut File) -> io::Result<()> {
	let empty_options = Options::new();
	let shb = SectionHeaderBlock::new_with_defaults(&empty_options);

	write_encodable(&shb, file)
		.await?;

	let idb = InterfaceDescriptionBlock::new(
		LinkType::Raw,
		0,
		&empty_options);

	write_encodable(&idb, file)
		.await?;

	Ok(())
}

async fn write_encodable<Enc: Encodable<std::io::Cursor<Vec<u8>>>>(enc: &Enc, file: &mut File) -> io::Result<()> {
	let mut cursor = Cursor::new(vec![]);

	enc.encode::<byteorder::NativeEndian>(&mut cursor).unwrap();

	file.write_all(&cursor.into_inner())
		.await?;

	Ok(())
}
