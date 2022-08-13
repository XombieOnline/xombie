use std::process::exit;

use tokio::signal::unix::{signal, SignalKind};

use warp::Filter;

#[tokio::main]
async fn main() {
    let routes = warp::any().map(|| "Hello, World!");

    let mut sigterm_stream = signal(SignalKind::terminate()).unwrap();

    tokio::select! {
        _ = warp::serve(routes).run(([0, 0, 0, 0], 80)) => {
            eprintln!("warp main loop quit")
        }
        _ = sigterm_stream.recv() => {
            println!("Received SIGTERM");
            exit(0)
        }
    }
}