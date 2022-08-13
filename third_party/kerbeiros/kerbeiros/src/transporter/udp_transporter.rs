use crate::{Result, Error};
use std::io;
pub use std::net::IpAddr;
use std::net::*;

use super::transporter_trait::*;

/// Send Kerberos messages over UDP
#[derive(Debug)]
pub struct UDPTransporter {
    dst_addr: SocketAddr,
}

impl UDPTransporter {
    pub fn new(dst_addr: SocketAddr) -> Self {
        return Self { dst_addr };
    }

    fn request_and_response_udp(&self, raw_request: &[u8]) -> io::Result<Vec<u8>> {
        let udp_socket = UdpSocket::bind("0.0.0.0:0")?;
        udp_socket.connect(self.dst_addr)?;

        udp_socket.send(raw_request)?;

        let data_length = self.calculate_response_size(&udp_socket)?;

        let mut raw_response = vec![0; data_length as usize];
        udp_socket.recv(&mut raw_response)?;

        return Ok(raw_response);
    }

    fn calculate_response_size(&self, udp_socket: &UdpSocket) -> io::Result<usize> {
        let mut raw_response = vec![0; 2048];
        let mut data_length = udp_socket.peek(&mut raw_response)?;
        while data_length == raw_response.len() {
            raw_response.append(&mut raw_response.clone());
            data_length = udp_socket.peek(&mut raw_response)?;
        }
        return Ok(data_length);
    }
}

impl Transporter for UDPTransporter {
    fn request_and_response(&self, raw_request: &[u8]) -> Result<Vec<u8>> {
        let raw_response = self
            .request_and_response_udp(raw_request)
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
            UDPTransporter::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 88));
        requester.request_and_response(&vec![]).unwrap();
    }
}
