use crate::cryptography::{AesSizes};
use crate::utils::random_bytes;

/// Generate an aleatory preamble to insert at the beginning of the
/// plaintext before AES encryption
pub fn generate_preamble(
    aes_sizes: &AesSizes
) -> Vec<u8> {
    return random_bytes(aes_sizes.block_size());
}
