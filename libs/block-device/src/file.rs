use std::io::{Read, Seek, SeekFrom, Write, self};
use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::BlockDevice;

pub struct FileBlockDevice<const BLOCK_SIZE: usize> {
    f: File,
}

impl<const BLOCK_SIZE: usize> FileBlockDevice<BLOCK_SIZE> {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<FileBlockDevice<BLOCK_SIZE>> {
        Ok(FileBlockDevice {
            f: OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?,
        })
    }

    pub fn seek_to_block(&mut self, block_num: u64) -> io::Result<()> {
        let byte_offset = block_num * (BLOCK_SIZE as u64);
        self.f.seek(SeekFrom::Start(byte_offset))?;

        Ok(())
    }
}

impl<const BLOCK_SIZE: usize> BlockDevice<BLOCK_SIZE> for FileBlockDevice<BLOCK_SIZE> {
	fn num_blocks(&mut self) -> u64 {
		todo!()
	}

	fn read_block(&mut self, block_num: u64) -> io::Result<[u8;BLOCK_SIZE]> {
        let mut buf = [0u8;BLOCK_SIZE];

        self.seek_to_block(block_num)?;
        self.f.read_exact(&mut buf)?;

        Ok(buf)
    }

    fn write_block(&mut self, block_num: u64, block: &[u8;BLOCK_SIZE]) -> io::Result<()> {
        self.seek_to_block(block_num)?;

        self.f.write_all(block)?;

        Ok(())
    }
}
