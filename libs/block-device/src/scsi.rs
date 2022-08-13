use std::fmt::Debug;

#[derive(Debug)]
pub enum CommandError<PlatError: Debug + Sized> {
	PlatError(PlatError),
	ReadError,
}

pub trait Target {
	type CommandPlatError: Debug + Sized;

	fn command_recv<Cmd: RecvCommand, Resp: Response>(&mut self, cmd: &Cmd) -> Result<(Resp, Status), CommandError<Self::CommandPlatError>>;
	fn command_send<Cmd: SendCommand, Dat: Data>(&mut self, cmd: &Cmd, data: &Dat) -> Result<Status, CommandError<Self::CommandPlatError>>;
}

pub trait Command {
    fn bytes<'a>(&'a self) -> &'a[u8];
    fn is_data_in(&self) -> bool;
}

pub trait RecvCommand: Command {
	type Response: Response;
}

pub trait SendCommand: Command {
	type Data: Data;
}

pub trait Response: Sized {
    fn max_len() -> usize;

    fn from_bytes(buf: &[u8]) -> Option<Self>;
}

pub trait Data: Sized {
	fn bytes<'a>(&'a self) -> &'a[u8];
	fn len() -> usize;
}

pub const SCSI_CONTROL: u8 = 0x00;

pub const SCSI_OP_REQUEST_SENSE_6:  u8 = 0x03;
pub const SCSI_OP_INQUIRY:          u8 = 0x12;
pub const SCSI_OP_READ_CAPACITY_10: u8 = 0x25;
pub const SCSI_OP_READ_10:          u8 = 0x28;
pub const SCSI_OP_WRITE_10:         u8 = 0x2a;

pub struct Read10Command<const BLOCK_SIZE: usize> {
    bytes: [u8;10],
}

impl<const BLOCK_SIZE: usize> Read10Command<BLOCK_SIZE> {
    pub fn new(lba: u32) -> Self {
        let lba_bytes = lba.to_be_bytes();
        Read10Command {
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

impl<const BLOCK_SIZE: usize> Command for Read10Command<BLOCK_SIZE> {
    fn bytes<'a>(&'a self) -> &'a[u8] {
        &self.bytes
    }

    fn is_data_in(&self) -> bool {
        true
    }
}

impl<const BLOCK_SIZE: usize> RecvCommand for Read10Command<BLOCK_SIZE> {
	type Response = Sector<BLOCK_SIZE>;
}

pub struct RequestSense6Command {
	bytes: [u8;6],
}

impl RequestSense6Command {
	pub fn new() -> Self {
		RequestSense6Command {
			bytes: [
				SCSI_OP_REQUEST_SENSE_6,
				0,
				0,
				0,
				ReadCapacity10Response::max_len() as u8,
				SCSI_CONTROL,
			]
		}
	}
}

impl Command for RequestSense6Command {
	fn bytes<'a>(&'a self) -> &'a[u8] {
		&self.bytes
	}

	fn is_data_in(&self) -> bool {
		true
	}
}

impl RecvCommand for RequestSense6Command {
	type Response = RequestSense6Response;
}

#[derive(Debug)]
pub struct Write10Command<const BLOCK_SIZE: usize> {
	bytes: [u8;10],
}

impl<const BLOCK_SIZE: usize> Write10Command<BLOCK_SIZE> {
	pub fn new(lba: u32) -> Self {
		let lba_bytes = lba.to_be_bytes();

		Write10Command {
			bytes: [
				SCSI_OP_WRITE_10,
				0b_000_0_1_000,
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

impl<const BLOCK_SIZE: usize> Command for Write10Command<BLOCK_SIZE> {
	fn bytes<'a>(&'a self) -> &'a[u8] {
		&self.bytes
	}

	fn is_data_in(&self) -> bool {
		false
	}
}

impl<const BLOCK_SIZE: usize> SendCommand for Write10Command<BLOCK_SIZE> {
	type Data = Sector<BLOCK_SIZE>;
}

pub struct ReadCapacity10Command {
    pub bytes: [u8;10],
}

impl ReadCapacity10Command {
    pub fn new() -> Self {
        ReadCapacity10Command {
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

impl Command for ReadCapacity10Command {
    fn bytes<'a>(&'a self) -> &'a[u8] {
        &self.bytes
    }

    fn is_data_in(&self) -> bool {
        true
    }
}

impl RecvCommand for ReadCapacity10Command {
    type Response = ReadCapacity10Response;
}

#[derive(Debug)]
pub struct Sector<const BLOCK_SIZE: usize> {
    pub bytes: [u8;BLOCK_SIZE],
}

impl<const BLOCK_SIZE: usize> Response for Sector<BLOCK_SIZE> {
    fn max_len() -> usize {
        BLOCK_SIZE
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        Some(Sector {
            bytes: buf.try_into().unwrap()
        })
    }
}

impl<const BLOCK_SIZE: usize> Data for Sector<BLOCK_SIZE> {
	fn bytes<'a>(&'a self) -> &'a[u8] {
		&self.bytes
	}

	fn len() -> usize {
		BLOCK_SIZE
	}
}

#[derive(Debug)]
pub struct RequestSense6Response {
	pub bytes: [u8;18],
}

impl Response for RequestSense6Response {
	fn max_len() -> usize {
		18
	}

	fn from_bytes(buf: &[u8]) -> Option<Self> {
		Some(RequestSense6Response {
			bytes: buf.try_into().unwrap(),
		})
	}
}

#[derive(Debug)]
pub struct ReadCapacity10Response {
    pub bytes: [u8;8],
}

impl ReadCapacity10Response {
	pub fn lba(&self) -> u32 {
		let bytes = [
			self.bytes[0], self.bytes[1],
			self.bytes[2], self.bytes[3],
		];

		u32::from_be_bytes(bytes)
	}

	pub fn sector_size(&self) -> u32 {
		let bytes = [
			self.bytes[4], self.bytes[5],
			self.bytes[6], self.bytes[7],
		];

		u32::from_be_bytes(bytes)
	}
}

impl Response for ReadCapacity10Response {
    fn max_len() -> usize {
        8
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        Some(ReadCapacity10Response {
            bytes: buf.try_into().unwrap(),
        })
    }
}

#[derive(Debug)]
pub enum Status {
	TransportRaw(Vec<u8>),
}
