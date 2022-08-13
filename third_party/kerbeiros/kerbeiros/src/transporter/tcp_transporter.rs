use crate::{Result, Error};
use std::io;
use std::io::{Read, Write};
use std::net::*;
use std::time::Duration;

use super::transporter_trait::*;

/// Send Kerberos messages over TCP
#[derive(Debug)]
pub struct TCPTransporter {
    dst_addr: SocketAddr,
}

impl TCPTransporter {
    pub fn new(dst_addr: SocketAddr) -> Self {
        return Self { dst_addr };
    }

    fn request_and_response_tcp(&self, raw_request: &[u8]) -> io::Result<Vec<u8>> {
        let mut tcp_stream = TcpStream::connect_timeout(&self.dst_addr, Duration::new(5, 0))?;

        let raw_sized_request = Self::set_size_header_to_request(raw_request);
        tcp_stream.write(&raw_sized_request)?;

        let mut len_data_bytes = [0 as u8; 4];
        tcp_stream.read_exact(&mut len_data_bytes)?;
        let data_length = u32::from_be_bytes(len_data_bytes);

        let mut raw_response: Vec<u8> = vec![0; data_length as usize];
        tcp_stream.read_exact(&mut raw_response)?;

        return Ok(raw_response);
    }

    fn set_size_header_to_request(raw_request: &[u8]) -> Vec<u8> {
        let request_length = raw_request.len() as u32;
        let mut raw_sized_request: Vec<u8> = request_length.to_be_bytes().to_vec();
        raw_sized_request.append(&mut raw_request.to_vec());

        return raw_sized_request;
    }
}

impl Transporter for TCPTransporter {
    fn request_and_response(&self, raw_request: &[u8]) -> Result<Vec<u8>> {
        let raw_response = self
            .request_and_response_tcp(raw_request)
            .map_err(|_| Error::NetworkError)?;
        return Ok(raw_response);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[should_panic(expected = "NetworkError")]
    #[test]
    fn test_request_networks_error() {
        let requester =
            TCPTransporter::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 88));
        requester.request_and_response(&vec![]).unwrap();
    }
}
