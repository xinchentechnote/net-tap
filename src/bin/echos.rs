use std::io::{Read, Write};
use std::net::TcpListener;

use clap::Parser;
use tracing::info;
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value = "8080")]
    port: u16,
}
fn main() {
    let args = Args::parse();
    let target = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(target.as_str()).unwrap();
    info!("server listening on {}", target);

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut buf = [0; 1024];
        let n = stream.read(&mut buf).unwrap();
        info!("Server received: {}", String::from_utf8_lossy(&buf[..n]));
        stream.write_all(&buf[..n]).unwrap();
    }
}
