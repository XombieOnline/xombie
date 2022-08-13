use async_trait::async_trait;

use crate::client::{ClientState, PacketProcessError};
use crate::client::service::Service;
use crate::client::tcp::{ServerImpl, ServerStack};

use xblive::sg::tcp::TcpHeader;

pub struct ForwardTcpService {
    server: ServerStack<ForwardServiceImpl>,
}

impl ForwardTcpService {
    pub fn new() -> Self {
        ForwardTcpService {
            server: ServerStack::new(Box::new(|| {
                Ok(ForwardServiceImpl {
                })
            }))
        }
    }
}

#[async_trait]
impl Service for ForwardTcpService {
    async fn on_tcp_packet<'a>(&mut self, header: &TcpHeader, packet: &[u8], state: &ClientState) -> Result<(), PacketProcessError> {
        self.server.on_packet(header, packet, state)
            .await
    }
}

struct ForwardServiceImpl {

}

#[async_trait]
impl ServerImpl for ForwardServiceImpl {
    async fn on_accept(&mut self) -> Result<(), PacketProcessError> {
        println!("Accepted connection");

        Ok(())
    }

    async fn on_incoming_data(&mut self, data: &[u8]) -> Result<(), PacketProcessError> {
        println!("on_incoming_data: {:02x?}", data);

        Ok(())
    }
}