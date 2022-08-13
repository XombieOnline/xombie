pub const UDP_PORT: u16 = 53;

#[derive(Clone, Copy, Debug)]
pub enum ServiceType {
    MachineAccountCreationService,
    AuthenticationService,
    TicketGrantingService,
}

#[derive(Debug)]
pub struct Service {
    pub service_type: ServiceType,
    pub partner_net: bool,
}

impl Service {
    pub fn from_domain_name(domain: &str) -> Option<Service> {
        Some(match domain {
            "as.part.xboxlive.com" => Service {
                service_type: ServiceType::AuthenticationService,
                partner_net: true,
            },
            "as.xboxlive.com" => Service {
                service_type: ServiceType::AuthenticationService,
                partner_net: false,
            },
            "macs.part.xboxlive.com" => Service {
                service_type: ServiceType::MachineAccountCreationService,
                partner_net: true,
            },
            "macs.xboxlive.com" => Service {
                service_type: ServiceType::MachineAccountCreationService,
                partner_net: false,
            },
            "tgs.part.xboxlive.com" => Service {
                service_type: ServiceType::TicketGrantingService,
                partner_net: true,
            },
            "tgs.xboxlive.com" => Service {
                service_type: ServiceType::TicketGrantingService,
                partner_net: false,
            },
            _ => return None,
        })
    }
}