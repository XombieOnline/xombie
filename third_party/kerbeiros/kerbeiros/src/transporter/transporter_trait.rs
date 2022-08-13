use crate::error::*;

/// Trait implemented by classes which deliver Kerberos messages
pub trait Transporter {
    /// Sends a message and retrieves the response
    fn request_and_response(&self, raw_request: &[u8]) -> Result<Vec<u8>>;
}
