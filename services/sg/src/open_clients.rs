use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, sync::RwLock, sync::RwLockWriteGuard, fmt};

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use xblive::sg::{SECURITY_PARAMETERS_INDEX_LEN, SecurityParametersIndex};

struct ClientTableEntry {
    spi: SecurityParametersIndex,
    peer: SocketAddr,
    pkt_queue: UnboundedSender<Vec<u8>>,
}

pub struct SpiReservation {
    spi: SecurityParametersIndex,
    client_table: Arc<RwLock<BTreeMap<SecurityParametersIndex, ClientTableEntry>>>,
}

impl SpiReservation {
    pub fn spi(&self) -> SecurityParametersIndex {
        self.spi
    }
}

impl fmt::Debug for SpiReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "SpiReservation(spi: {:?})", self.spi)
    }
}

impl std::ops::Drop for SpiReservation {
    fn drop(&mut self) {
        println!("Dropping client spi: {:?}", self.spi);
        if let Ok(mut client_table) = self.client_table.write() {
            let _prev = client_table.remove(&self.spi);
        }
    }
}

pub struct OpenClients {
    last_spi: u32,
    clients: Arc<RwLock<BTreeMap<SecurityParametersIndex, ClientTableEntry>>>,
}

// SPI(0) is special cased for connection initialization
const MAX_CLIENT_NUM: usize = (1 << (SECURITY_PARAMETERS_INDEX_LEN * 8)) - 1;

impl OpenClients {
    pub fn new() -> Self {
        OpenClients {
            last_spi: 0,
            clients: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub fn dispatch_packet(&self, spi: SecurityParametersIndex, peer: SocketAddr, buf: Vec<u8>) {
        if let Ok(client_table) = self.clients.read() {
            if let Some(client_table_entry) = client_table.get(&spi) {
                if client_table_entry.spi == spi && client_table_entry.peer == peer {
                    let _ = client_table_entry.pkt_queue.send(buf);
                } else {
                    eprintln!("Packet did not match spi or peer {:x?} {} {:02x?}", spi, peer, buf);
                }
            } else {
                eprintln!("Unable to find client table for packet {:x?} {} {:02x?}", spi, peer, buf);
            }
        }
    }

    pub fn allocate_spi(&mut self, peer: SocketAddr) -> Option<(SpiReservation, UnboundedReceiver<Vec<u8>>)> {
        let (new_spi, pkt_receiver) = {
            let mut client_table = self.clients.write()
                .ok()?;

            let new_spi = next_open_spi(&mut self.last_spi, &client_table)?;
            let (pkt_sender, pkt_receiver) = unbounded_channel();

            let client_table_entry = ClientTableEntry {
                spi: new_spi,
                peer,
                pkt_queue: pkt_sender,
            };
    
            if let Some(_) = client_table.insert(new_spi, client_table_entry) {
                panic!("Somehow already had new_spi reserved");
            }

            (new_spi, pkt_receiver)
        };

        let spi_reservation = SpiReservation {
            spi: new_spi,
            client_table: self.clients.clone(),
        };

        Some((spi_reservation, pkt_receiver))
    }
}

fn next_open_spi(
    last_spi: &mut u32,
    client_table: &RwLockWriteGuard<'_, BTreeMap<SecurityParametersIndex, ClientTableEntry>>)
-> Option<SecurityParametersIndex>
{
    if client_table.len() == MAX_CLIENT_NUM {
        return None;
    }

    loop {
        let next_spi_u32 = last_spi.wrapping_add(0x100);
        let next_spi = SecurityParametersIndex::from(next_spi_u32);

        *last_spi = next_spi_u32;

        if next_spi == SecurityParametersIndex::EMPTY || client_table.contains_key(&next_spi) {
            continue;
        } else {
            return Some(next_spi)
        }
    }
}