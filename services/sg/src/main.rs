use clap::Parser;
use xombie_matchmaking::Matchmaking;

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::process::exit;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::signal::unix::{signal, SignalKind};

use tokio::sync::RwLock;
use tokio_postgres::Client;

use xblive::sg::packet::{Header, PacketCategorizaton};
use xombie::db::connect_db_client;

mod client;
mod init;
mod ip_conversion;
mod open_clients;
mod secrets;
mod tracer;
mod user;

const MTU_SIZE: usize = 1500;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser, default_value_t = String::from("0.0.0.0"))]
    sg_addr: String,

    #[clap(short, long, value_parser, default_value_t = xblive::sg::UDP_PORT)]
    sg_port: u16,

    #[clap(short, long, value_parser, default_value_t = String::from("db"))]
    pg_addr: String,

    #[clap(short, long, value_parser, default_value_t = 5432)]
    pg_port: u16,

    #[clap(short, long, value_parser, default_value_t = String::from("postgres"))]
    pg_user: String,

    #[clap(short, long, value_parser, default_value_t = String::from("postgres"))]
    pg_password: String,
}

#[derive(Debug)]
pub struct Services {
    pub pg: Client,
    pub matchmaking: Matchmaking,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let pg = connect_db_client(
        &args.pg_addr,
        args.pg_port,
        &args.pg_user,
        &args.pg_password)
        .await
        .unwrap();

    let matchmaking = Matchmaking::new();

    let services = Arc::new(Services {
        pg,
        matchmaking,
    });

    let addr = format!("{}:{}", args.sg_addr, args.sg_port);

    let socket = UdpSocket::bind(&addr).await?;

    println!("SG Listening on: {}", socket.local_addr()?);

    let mut sigterm_stream = signal(SignalKind::terminate()).unwrap();

    tokio::select! {
        _ = run(socket, services) => {
            eprintln!("Main loop quit")
        }
        _ = sigterm_stream.recv() => {
            println!("Received SIGTERM");
            exit(0)
        }
    }

    Ok(())
}

async fn run(socket: UdpSocket, services: Arc<Services>) -> Result<(), io::Error> {
    simple_logger::SimpleLogger::new().init().unwrap();

    let socket = Arc::new(socket);

    let client_table = Arc::new(RwLock::new(open_clients::OpenClients::new()));

    loop {
        let mut buf = vec![0;MTU_SIZE];

        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(valid_parts) => valid_parts,
            Err(e) => {
                eprintln!("Error reading from socket: {:?}", e);
                return Err(e);
            }
        };

        buf.truncate(len);

        let tx_socket = socket.clone();

        let services = services.clone();

        let client_table = client_table.clone();

        process_packet(buf, peer, tx_socket, services, client_table)
            .await
    }
}

async fn process_packet(buf: Vec<u8>, peer: SocketAddr, tx_socket: Arc<UdpSocket>, services: Arc<Services>, client_table: Arc<RwLock<open_clients::OpenClients>>) {
    let header = match Header::from_buffer(&buf) {
        Some(header) => header,
        None => {
            eprintln!("Throwing away tiny packet from {}: {:02x?}", peer, buf);
            return;
        }
    };

    use PacketCategorizaton::*;
    match header.categorize_packet() {
        Invalid => {
            eprintln!("Throwing away invalid packet from {}: {:02x?}", peer, buf);
            return;
        }
        ControlInit => {
            tokio::spawn(async move {
                init::process_control_init_packet(buf, peer, tx_socket, services, client_table).await
            });
        }
        Connection => {
            client_table.read()
                .await
                .dispatch_packet(header.spi(), peer, buf)
        }
    }
}
