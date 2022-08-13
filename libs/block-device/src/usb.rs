use rusb::{Device, DeviceDescriptor, DeviceHandle, Context, UsbContext};

use std::io;
use std::time::Duration;

use crate::BlockDevice;
use crate::scsi;
use crate::scsi::Target;

#[derive(Debug)]
pub enum UsbMassStorageBlockDeviceOpenError {
	ParameterNotValid(&'static str),
	UnableToCreateUsbContext(rusb::Error),
	UnableToOpenUsbDevice,
	UnableToReadConfigDescriptor(rusb::Error),
	WrongNumberOfInterfaces(usize),
	WrongNumberOfinterfaceDescriptors(usize),
	WrongNumberOfEndpoints(usize),
	UnableToSetActiveConfiguration(rusb::Error),
	UnableToClaimInterface(rusb::Error),
	UnableToSetAlternateSetting(rusb::Error),
}

#[allow(dead_code)]
pub struct UsbMassStorageBlockDevice  {
	scsi_target: MassStorageScsiTarget,
	num_blocks: u64,
	sector_size: usize,
}

impl UsbMassStorageBlockDevice {
	pub fn open(vid: &str, pid: &str) -> Result<UsbMassStorageBlockDevice, UsbMassStorageBlockDeviceOpenError> {
		use UsbMassStorageBlockDeviceOpenError::*;

		let vid = id_from_hex(vid)
			.ok_or(ParameterNotValid("vid"))?;

		let pid = id_from_hex(pid)
			.ok_or(ParameterNotValid("pid"))?;

		let mut scsi_target = MassStorageScsiTarget::open(vid, pid)?;

		let read_capacity_cmd = scsi::ReadCapacity10Command::new();

		let (resp, _) = scsi_target.command_recv::<_, scsi::ReadCapacity10Response>(&read_capacity_cmd)
			.unwrap();

		Ok(UsbMassStorageBlockDevice {
			scsi_target,
			num_blocks: (resp.lba() + 1) as u64,
			sector_size: resp.sector_size() as usize,
		})
	}
}

impl<const BLOCK_SIZE: usize> BlockDevice<BLOCK_SIZE> for UsbMassStorageBlockDevice {
	fn num_blocks(&mut self) -> u64 {
		self.num_blocks
	}

	fn read_block(&mut self, block_num: u64) -> io::Result<[u8;BLOCK_SIZE]> {
		let read_command = scsi::Read10Command::<BLOCK_SIZE>::new(block_num as u32);

		let (sector, status) = self.scsi_target.command_recv::<_, scsi::Sector<BLOCK_SIZE>>(&read_command)
			.unwrap();

		println!("<- {:4x} {:02x?}", block_num, status);

		Ok(sector.bytes)
	}

	fn write_block(&mut self, block_num: u64, block: &[u8;BLOCK_SIZE]) -> io::Result<()> {
		let write_cmd = scsi::Write10Command::<BLOCK_SIZE>::new(block_num as u32);

		let sector_data = scsi::Sector {
			bytes: *block,
		};

		println!("{} {:x?} {:02x?}", block_num, write_cmd, sector_data);

		let status = self.scsi_target.command_send(&write_cmd, &sector_data)
			.unwrap();

		println!("-> {:4x} {:02x?}", block_num, status);

		Ok(())
	}
}

#[allow(dead_code)]
pub struct MassStorageScsiTarget {
	device: Device<Context>,
	device_desc: DeviceDescriptor,
	handle: DeviceHandle<Context>,
	config: u8,
	iface: u8,
	setting: u8,
	in_address: u8,
	out_address: u8,

	tag: u32,
}

impl MassStorageScsiTarget {
	pub fn open(vid: u16, pid: u16) -> Result <MassStorageScsiTarget, UsbMassStorageBlockDeviceOpenError> {
		use UsbMassStorageBlockDeviceOpenError::*;

		let mut ctx = rusb::Context::new()
			.map_err(|err| UnableToCreateUsbContext(err))?;

		let (device, device_desc, mut handle) = open_device(&mut ctx, vid, pid)
			.ok_or(UnableToOpenUsbDevice)?;

		let config_desc = device.config_descriptor(0)
			.map_err(|err| UnableToReadConfigDescriptor(err))?;

		let interfaces: Vec<_> = config_desc.interfaces().collect();

		if interfaces.len() != 1 {
			return Err(WrongNumberOfInterfaces(interfaces.len()))
		}

		let interface_descriptors: Vec<_> = interfaces[0].descriptors().collect();

		if interface_descriptors.len() != 1 {
			return Err(WrongNumberOfinterfaceDescriptors(interface_descriptors.len()))
		}

		let endpoints: Vec<_> = interface_descriptors[0].endpoint_descriptors().collect();

		if endpoints.len() != 2 {
			return Err(WrongNumberOfEndpoints(endpoints.len()))
		}

		let in_desc = &endpoints[0];
        let out_desc = &endpoints[1];

        let config = config_desc.number();
        let iface = interface_descriptors[0].interface_number();
        let setting = interface_descriptors[0].setting_number();

        handle.set_active_configuration(config)
            .map_err(|err| UnableToSetActiveConfiguration(err))?;

        handle.claim_interface(iface)
            .map_err(|err| UnableToClaimInterface(err))?;

        handle.set_alternate_setting(iface, setting)
            .map_err(|err| UnableToSetAlternateSetting(err))?;

		Ok(MassStorageScsiTarget {
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
}

#[derive(Debug)]
pub enum CommandError {
	SendCommandBlock(rusb::Error),
	ReceiveResponse(rusb::Error),
	ReadingStatus(rusb::Error),
	CommandStatusWordFailure{ status: u8, residue: u32 },
}

impl scsi::Target for MassStorageScsiTarget {
	type CommandPlatError = CommandError;

	fn command_recv<Cmd: scsi::RecvCommand, Resp: scsi::Response>(&mut self, cmd: &Cmd) -> Result<(Resp, scsi::Status), scsi::CommandError<CommandError>> {
		let tag = self.consume_tag();

        let command_block = CommandBlockWrapper::new_from_recv_cmd(cmd, tag);

        let _ = self.handle.write_bulk(
            self.out_address,
            &command_block.0,
            Duration::from_secs(1))
            .map_err(|err| scsi::CommandError::PlatError(CommandError::SendCommandBlock(err)))?;

		let mut buf = [0u8;512];

		let buf = &mut buf[..Resp::max_len()];

		let _len_recevied = self.handle.read_bulk(
			self.in_address,
			buf,
			Duration::from_secs(1))
			.map_err(|err| scsi::CommandError::PlatError(CommandError::ReceiveResponse(err)))?;

		// println!("RX: {} {:02x?}", len_recevied, buf);

		let resp = Resp::from_bytes(buf).unwrap();

        let mut csw = CommandStatusWrapper::new();

        let _ = self.handle.read_bulk(
            self.in_address,
            &mut csw.0,
            Duration::from_secs(1))
            .map_err(|err| scsi::CommandError::PlatError(CommandError::ReadingStatus(err)))?;

		if csw.status() != 0 {
			return Err(scsi::CommandError::PlatError(CommandError::CommandStatusWordFailure {
				status: csw.status(),
				residue: csw.residue(),
			}))
		}

        Ok((resp, scsi::Status::TransportRaw(csw.0.to_vec())))
	}

	fn command_send<Cmd: scsi::SendCommand, Data: scsi::Data>(&mut self, cmd: &Cmd, data: &Data) -> Result<scsi::Status, scsi::CommandError<Self::CommandPlatError>> {
		let tag = self.consume_tag();

		println!("cmd: {:02x?}", cmd.bytes());

		let command_block = CommandBlockWrapper::new_from_send_cmd(cmd, data, tag);

        let _ = self.handle.write_bulk(
            self.out_address,
            &command_block.0,
            Duration::from_secs(1))
            .map_err(|err| scsi::CommandError::PlatError(CommandError::SendCommandBlock(err)))?;

		let sent = self.handle.write_bulk(
			self.out_address,
			data.bytes(),
			Duration::from_secs(1))
			.unwrap();

		println!("sent: {}", sent);

		let mut csw = CommandStatusWrapper::new();

		let _ = self.handle.read_bulk(
			self.in_address,
			&mut csw.0,
			Duration::from_secs(1))
			.map_err(|err| scsi::CommandError::PlatError(CommandError::ReadingStatus(err)))?;

		if csw.status() != 0 {
			return Err(scsi::CommandError::PlatError(CommandError::CommandStatusWordFailure {
				status: csw.status(),
				residue: csw.residue(),
			}))
		}

		Ok(scsi::Status::TransportRaw(csw.0.to_vec()))
	}
}

fn id_from_hex(s: &str) -> Option<u16> {
    let mut out = [0u8;2];
    hex::decode_to_slice(s, &mut out).ok()?;

    Some(u16::from_be_bytes(out))
}

fn open_device(
    ctx: &mut Context,
    vid: u16,
    pid: u16,
) -> Option<(Device<Context>, DeviceDescriptor, DeviceHandle<Context>)> {
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

struct CommandBlockWrapper([u8;31]);

impl CommandBlockWrapper {
    fn new_from_recv_cmd<Cmd: scsi::RecvCommand>(cmd: &Cmd, tag: u32) -> CommandBlockWrapper {
		use scsi::Response;

		Self::new(tag, Cmd::Response::max_len() as u32, true, cmd.bytes())

		// let tag_bytes = tag.to_le_bytes();
        // let data_transfer_len = Cmd::Response::max_len() as u32;
        // let data_transfer_len_bytes = data_transfer_len.to_le_bytes();

        // let mut bytes = [0u8;31];

        // bytes[0..4].copy_from_slice(&[0x55, 0x53, 0x42, 0x43]);
        // bytes[4..8].copy_from_slice(&tag_bytes);
        // bytes[8..12].copy_from_slice(&data_transfer_len_bytes);
        // bytes[12] = if cmd.is_data_in() {
        //     0x80
        // } else {
        //     0
        // };
        // bytes[13] = 0; // lun 0

        // let cmd_bytes = cmd.bytes();
        // bytes[14] = (cmd_bytes.len() as u8) << 3;

        // let cbwcb_base = 15;
        // let cbwcb_end = cbwcb_base + cmd_bytes.len();

        // bytes[cbwcb_base..cbwcb_end].copy_from_slice(cmd_bytes);

        // CommandBlockWrapper(bytes)
    }

	fn new_from_send_cmd<Cmd: scsi::SendCommand, Data: scsi::Data>(cmd: &Cmd, data: &Data, tag: u32) -> CommandBlockWrapper {
		Self::new(tag, data.bytes().len() as u32, false, cmd.bytes())
	}

	fn new(tag: u32, data_transfer_len: u32, is_data_in: bool, cmd_bytes: &[u8]) -> CommandBlockWrapper {
		let tag_bytes = tag.to_le_bytes();
        let data_transfer_len_bytes = data_transfer_len.to_le_bytes();

		let mut bytes = [0u8;31];
		bytes[0..4].copy_from_slice(&[0x55, 0x53, 0x42, 0x43]);
		bytes[4..8].copy_from_slice(&tag_bytes);
		bytes[8..12].copy_from_slice(&data_transfer_len_bytes);
		bytes[12] = if is_data_in {
			0x80
		} else {
			0x00
		};

		bytes[13] = 0; // lun 0

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

	fn residue(&self) -> u32 {
		let bytes = [
			self.0[8], self.0[9],
			self.0[10], self.0[11],
		];

		u32::from_le_bytes(bytes)
	}

	fn status(&self) -> u8 {
		self.0[12]
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
