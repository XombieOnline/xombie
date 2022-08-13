//! Module to provide means to transport Kerberos messages
//!

use std::net::*;

mod transporter_trait;
pub use transporter_trait::*;

mod tcp_transporter;
use tcp_transporter::*;

mod udp_transporter;
use udp_transporter::*;

/// Default Kerberos port 88
pub const DEFAULT_KERBEROS_PORT: u16 = 88;

/// Transport protocols available to send Kerberos messages
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TransportProtocol {
    TCP,
    UDP,
}

/// Generates a transporter given and address and transport protocol
pub fn new_transporter(
    host_address: IpAddr,
    transport_protocol: TransportProtocol,
) -> Box<dyn Transporter> {
    let dst_addr = SocketAddr::new(host_address, DEFAULT_KERBEROS_PORT);

    match transport_protocol {
        TransportProtocol::TCP => {
            return Box::new(TCPTransporter::new(dst_addr));
        }
        TransportProtocol::UDP => {
            return Box::new(UDPTransporter::new(dst_addr));
        }
    }
}
