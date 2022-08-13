#![warn(rust_2018_idioms)]

#[macro_use]
extern crate nom;

use clap::Parser;

use std::error::Error;
use std::io;
use std::process::exit;

use tokio::sync::RwLock;

use tokio::net::UdpSocket;
use tokio::signal::unix::{signal, SignalKind};

use xombie::db::*;

mod packet;

const MTU_SIZE: usize = 1500;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser, default_value_t = String::from("0.0.0.0"))]
    dns_addr: String,

    #[clap(short, long, value_parser, default_value_t = xblive::dns::UDP_PORT)]
    dns_port: u16,

    #[clap(short, long, value_parser, default_value_t = String::from("db"))]
    pg_addr: String,

    #[clap(short, long, value_parser, default_value_t = 5432)]
    pg_port: u16,

    #[clap(short, long, value_parser, default_value_t = String::from("postgres"))]
    pg_user: String,

    #[clap(short, long, value_parser, default_value_t = String::from("postgres"))]
    pg_password: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let pg_client = xombie::db::connect_db_client(
        &args.pg_addr,
        args.pg_port,
        &args.pg_user,
        &args.pg_password
    ).await.unwrap();

    let cluster_addrs = get_cluster_addrs(&pg_client)
        .await
        .unwrap();

    let mut sigterm_stream = signal(SignalKind::terminate())
        .unwrap();

    let addr = format!("{}:{}", args.dns_addr, args.dns_port);

    let socket = UdpSocket::bind(&addr).await?;

    println!("server up: {}", addr);

    let server = Server {
        socket,
        buf: [0;MTU_SIZE],
        cluster_addrs: RwLock::new(cluster_addrs),
    };

    tokio::select! {
        _ = server.run() => {
            eprintln!("server exited main loop")
        }
        _ = sigterm_stream.recv() => {
            println!("Received SIGTERM");
            exit(0)
        }
    }

    Ok(())
}

struct Server {
    socket: UdpSocket,
    buf: [u8;MTU_SIZE],
    cluster_addrs: RwLock<ClusterInfo>,
}

impl Server {
    async fn run(self) -> Result<(), io::Error> {
        let Server {
            socket,
            mut buf,
            cluster_addrs,
        } = self;

        loop {
            let (size, peer) = socket.recv_from(&mut buf).await?;

            let pkt_buffer = &buf[0..size];

            println!("Recevied {} byte packet from {}", pkt_buffer.len(), peer);

            let request = match packet::Packet::from_buffer(pkt_buffer) {
                Ok((_, packet)) => packet,
                Err(e) => {
                    eprintln!("Error parsing DNS request from peer {}: {:?}", peer, e);
                    continue;
                }
            };

            let mut response = request.clone();
            response.header.flags = 0x8100;
            for query in request.queries {
                let query_name = packet::name_from_components(&query.name)
                    .to_lowercase();

                let cluster_addrs = cluster_addrs.read().await;

                use xblive::dns::ServiceType::*;
                let addr = match xblive::dns::Service::from_domain_name(&query_name)
                    .map(|service| service.service_type)
                {
                    Some(MachineAccountCreationService) => cluster_addrs.kdc_nodes[0],
                    Some(AuthenticationService) => cluster_addrs.kdc_nodes[0],
                    Some(TicketGrantingService) => cluster_addrs.kdc_nodes[0],
                    None => {
                        eprintln!("Request for unknown domain from {}: {}", peer, query_name);
                        continue;
                    }
                };

                response.answers.push(packet::Answer {
                    qname: query.name.clone(),
                    dns_type: 1,
                    class: 1,
                    ttl: 117,
                    data: addr.to_vec(),
                });
            }
            response.header.answer_rrs = response.answers.len() as u16;
            response.header.authority_rrs = 0;
            response.header.addition_rrs = 0;

            println!("Sending to \"{}\": {:x?}", peer, response);

            let mut tx_buffer = vec![];

            if let Err(err) = response.marshal(&mut tx_buffer) {
                eprintln!("Unable to marsal response packet {:x?}: {:?}", response, err);
                continue;
            }

            if let Err(err) = socket.send_to(&mut tx_buffer, &peer).await {
                eprintln!("Unable to send response packet to {}: {:?}", peer, err);
            }
        }
    }
}
