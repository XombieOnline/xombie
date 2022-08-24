use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use smoltcp_user_vpn::tcp::AcceptFn;
use xblive::{sg::{tcp::TcpHeader, packet::Packet}, net::InAddr};

use crate::client::{ClientState, PacketProcessError, ServiceMapping, forward, local};

pub mod matchmaking;
pub mod presence;
pub mod terms_of_use;
mod unimplemented;

#[derive(Debug)]
enum ServiceKind {
    Unimplemented,
    ForwardTcp,
    LocalTcp(fn(Arc<ClientState>) -> AcceptFn),
}

#[derive(Debug)]
#[allow(dead_code)]
struct ServiceInfo {
    pub kind: ServiceKind,
    pub id: u32,
    pub name: &'static str,
}

static SERVICE_INFO: phf::Map<u32, ServiceInfo> = phf::phf_map! {
    1u32 => ServiceInfo {
        kind: ServiceKind::LocalTcp(presence::new_presence_connection),
        id: 1,
        name: "Presence",
    },
    2u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 2,
        name: "String",
    },
    3u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 3,
        name: "Auto Update",
    },
    4u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 4,
        name: "Content Available"
    },
    5u32 => ServiceInfo {
        kind: ServiceKind::ForwardTcp,
        id: 5,
        name: "User Account Creation",
    },
    6u32 => ServiceInfo {
        kind: ServiceKind::LocalTcp(matchmaking::new_matchmaking_connection),
        id: 6,
        name: "Matchmaking",
    },
    7u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 7,
        name: "Stats",
    },
    8u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 8,
        name: "Feedback"
    },
    9u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 9,
        name: "Billing",
    },
    10u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 10,
        name: "Diagnostic",
    },
    11u32 => ServiceInfo {
        kind: ServiceKind::LocalTcp(terms_of_use::new_terms_of_use_connection),
        id: 11,
        name: "Terms of Use",
    },
    12u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 12,
        name: "Signature",
    },
    13u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 13,
        name: "Query",
    },
    14u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 14,
        name: "Resolve",
    },
    15u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 15,
        name: "Storage",
    },
    16u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 16,
        name: "Arbitration",
    },
    17u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 17,
        name: "Game Data",
    },
    18u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 18,
        name: "Messaging"
    },
    19u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 19,
        name: "Teams",
    },
    20u32 => ServiceInfo {
        kind: ServiceKind::Unimplemented,
        id: 20,
        name: "NAT Type Detection",
    },
};

#[derive(Debug)]
pub enum ServiceInitError {
}

#[async_trait]
pub trait Service {
    async fn on_tcp_packet<'a>(&mut self, header: &TcpHeader, packet: &[u8], state: &ClientState) -> Result<(), PacketProcessError>;
}

struct UnimplementedService {
    info: Option<&'static ServiceInfo>,
}

#[async_trait]
impl Service for UnimplementedService {
    async fn on_tcp_packet<'a>(&mut self, header: &TcpHeader, packet: &[u8], _state: &ClientState) -> Result<(), PacketProcessError> {
        println!("Packet info: {:?} {:?} {:02x?}", self.info, header, packet);

        Ok(())
    }
}

#[derive(Debug)]
pub enum ServiceTableCreateError {
    UnknownService(u32),
    ServiceExistsTwice(u32),
}

pub struct ServiceTable {
    services: BTreeMap<u16, Box<dyn Service + Send>>,
}

impl ServiceTable {
    pub fn new(mappings: &[ServiceMapping], client_addr: InAddr, server_addr: InAddr, state: &Arc<ClientState>) -> Result<Self, ServiceTableCreateError> {
        let mut services: BTreeMap<u16, Box<dyn Service + Send>> = BTreeMap::new();

        for mapping in mappings {
            let info = SERVICE_INFO.get(&mapping.id)
                .ok_or(ServiceTableCreateError::UnknownService(mapping.id))?;

            let service: Box<dyn Service + Send> = match info.kind {
                ServiceKind::Unimplemented => {
                    Box::new(UnimplementedService {
                        info: Some(info),
                    })
                }
                ServiceKind::ForwardTcp => {
                    Box::new(forward::ForwardTcpService::new())
                }
                ServiceKind::LocalTcp(new_conn) => {
                    let port = (info.id + 100) as u16;
                    Box::new(local::LocalTcpService::new(client_addr, server_addr, port, new_conn(state.clone()), state))
                }
            };

            if let Some(_) = services.insert(mapping.port, service) {
                return Err(ServiceTableCreateError::ServiceExistsTwice(info.id))
            }
        }

        Ok(ServiceTable {
            services,
        })
    }

    pub async fn on_tcp_packet<'a>(&mut self, header: &TcpHeader, packet: &Packet, state: &ClientState) -> Result<(), PacketProcessError> {
        self.lookup_service(header.dst)?
            .on_tcp_packet(header, packet.payload(), state)
            .await
    }

    fn lookup_service<'a>(&'a mut self, port: u16) -> Result<&'a mut Box<dyn Service + Send>, PacketProcessError> {
        self.services.get_mut(&port)
            .ok_or(PacketProcessError::UnauthorizedService(port))
    }
}
