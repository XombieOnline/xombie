use std::io;
use std::sync::{Arc, Mutex};

use crate::BlockDevice;

pub struct PartitionBlockDevice<const BLOCK_SIZE: usize> {
    backing: Arc<Mutex<dyn BlockDevice<BLOCK_SIZE>>>,
    base_block: u64,
    num_blocks: Option<u64>,
}

impl<const BLOCK_SIZE: usize> PartitionBlockDevice<BLOCK_SIZE> {
    pub fn new(
        backing: Arc<Mutex<dyn BlockDevice<BLOCK_SIZE>>>,
        base_block: u64,
        num_blocks: Option<u64>,
    ) -> Self {
        PartitionBlockDevice {
            backing,
            base_block,
            num_blocks,
        }
    }

    fn translate_and_bounds_check(&self, block_num: u64) -> io::Result<u64> {
        let phys_block_num = block_num + self.base_block;

        let last_block_num = self.last_block_num()
            .unwrap_or(u64::MAX);

        if phys_block_num > last_block_num {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Block {} out of bounds", block_num)
            ))
        }

        Ok(phys_block_num)
    }

    fn last_block_num(&self) -> Option<u64> {
        self.num_blocks.map(|num_blocks| self.base_block + num_blocks - 1 )
    }
}

impl<const BLOCK_SIZE: usize> BlockDevice<BLOCK_SIZE> for PartitionBlockDevice<BLOCK_SIZE> {
	fn num_blocks(&mut self) -> u64 {
		todo!()
	}

	fn read_block(&mut self, block_num: u64) -> io::Result<[u8;BLOCK_SIZE]> {
        let phys_block_num = self.translate_and_bounds_check(block_num)?;

        self.backing
            .lock()
            .unwrap()
            .read_block(phys_block_num)
    }

    fn write_block(&mut self, block_num: u64, block: &[u8;BLOCK_SIZE]) -> io::Result<()> {
        let phys_block_num = self.translate_and_bounds_check(block_num)?;

        self.backing
            .lock()
            .unwrap()
            .write_block(phys_block_num, block)
    }
}
