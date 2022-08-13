use md4::{Digest, Md4};

pub fn md4(bytes: &[u8]) -> Vec<u8> {
    return Md4::digest(&bytes).to_vec();
}
