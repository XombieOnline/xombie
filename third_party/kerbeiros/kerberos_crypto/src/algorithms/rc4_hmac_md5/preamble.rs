use crate::utils::random_bytes;

/// Generate an aleatory preamble to insert at the beginning of the
/// plaintext before RC4 encryption
pub fn generate_preamble() -> Vec<u8> {
    return random_bytes(8);
}
