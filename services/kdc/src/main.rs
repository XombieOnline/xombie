use clap::Parser;

use kerberos_asn1::Asn1Object;

use std::error::Error;
use std::net::SocketAddr;
use std::io;
use std::process::exit;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::signal::unix::{signal, SignalKind};

use tokio_postgres::Client;

use xombie::db::*;
use xombie::krb::*;

use crate::ticket_granting::process_tgs_request;

mod auth;
mod krb;
mod macs;
mod ticket_granting;

const MTU_SIZE: usize = 1500;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser, default_value_t = String::from("0.0.0.0"))]
    kdc_addr: String,

    #[clap(short, long, value_parser, default_value_t = UDP_PORT)]
    kdc_port: u16,

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

    let client = connect_db_client(
        &args.pg_addr,
        args.pg_port,
        &args.pg_user,
        &args.pg_password
    ).await.unwrap();

    let client = Arc::new(client);

    let addr = format!("{}:{}", args.kdc_addr, args.kdc_port);

    let socket = UdpSocket::bind(&addr).await?;
    println!("Listening on: {}", socket.local_addr()?);

    let mut sigterm_stream = signal(SignalKind::terminate()).unwrap();

    tokio::select! {
        _ = run(socket, client) => {
            eprintln!("Main loop quit")
        }
        _ = sigterm_stream.recv() => {
            println!("Received SIGTERM");
            exit(0)
        }
    }

    Ok(())
}

async fn run(socket: UdpSocket, client: Arc<Client>) -> Result<(), io::Error> {
    let socket = Arc::new(socket);

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

        let client = client.clone();

        tokio::spawn(async move {
            process_packet(buf, peer, tx_socket, client)
                .await
        });
    }
}

trait Phi<T> {
    fn phi(self) -> T;
}

impl<T> Phi<T> for Result<T, T> {
    fn phi(self) -> T {
        match self {
            Ok(ok) => ok,
            Err(err) => err,
        }
    }
}

async fn process_packet(buf: Vec<u8>, peer: SocketAddr, tx_socket: Arc<UdpSocket>, client: Arc<Client>) {
    let stime = now();

    println!("Received {} byte packet from {}: {:02x?}", buf.len(), peer, buf);

    let output_pkt = match krb::request_type(&buf) {
        Some(krb::RequestType::As(as_req)) => {
            let rep = if as_req.req_body.sname == Some(xblive::krb::macs_sname()) {
                macs::process_macs_request(as_req, stime, &client)
                    .await
            } else {
                auth::process_as_req(as_req, stime, &client)
                    .await
            };

            println!("Sending to {}: {:02x?}", peer, rep);

            rep.map(|as_rep| as_rep.build())
        }
        Some(krb::RequestType::Tgs(tgs_req)) => {
            let rep = process_tgs_request(tgs_req, stime, &client)
                .await;

            println!("Sending to {}: {:02x?}", peer, rep);

            rep.map(|tgs_rep| tgs_rep.build())
        }
        None => {
            todo!("unknown req: {:02x?}", buf)
        }
    };

    let output_buf = output_pkt
        .map_err(|krb_error| {
            eprintln!("Error: Sending: {:?} to {:?}", krb_error, peer);
            krb_error.build()
        }).phi();

    match tx_socket.send_to(&output_buf, peer).await {
        Ok(sent_len) => {
            if sent_len != output_buf.len() {
                eprintln!("Error: couldn't send full packet to {:?}: {} != {}",
                    peer,
                    sent_len,
                    output_buf.len())
            }
        }
        Err(err) => eprintln!("Error sending to {:?}: {:?}", peer, err),
    };

}
