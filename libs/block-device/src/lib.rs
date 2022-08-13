use std::io;

pub mod file;
pub mod partition;
#[cfg(feature = "scsi")]
pub mod scsi;
#[cfg(feature = "usb")]
pub mod usb;

pub trait BlockDevice<const BLOCK_SIZE: usize> {
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn num_blocks(&mut self) -> u64;

    fn read_block(&mut self, block_num: u64) -> io::Result<[u8;BLOCK_SIZE]>;
    fn write_block(&mut self, block_num: u64, block: &[u8;BLOCK_SIZE]) -> io::Result<()>;

    fn read_sequence_to_vec(&mut self, base_block: u64, num_blocks: usize) -> io::Result<Vec<u8>> {
        let mut result = vec![];

        for i in 0..num_blocks {
            let block = self.read_block(base_block + i as u64)?;
            result.extend_from_slice(&block);
        }

        Ok(result)
    }

    fn write_sequence(&mut self, buf: &[u8], base_block: u64) -> io::Result<()> {
        if buf.len() % BLOCK_SIZE != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "Buffer length not multiple of block size"))
        }

        for (i, block) in buf.chunks(BLOCK_SIZE).enumerate() {
            let block = block.try_into().unwrap();
            self.write_block(base_block + i as u64, block)?;
        }
        
        Ok(())
    }
}
