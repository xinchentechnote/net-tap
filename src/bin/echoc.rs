use std::io::{Read, Write};
use std::net::TcpStream;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    ip: String,
    #[arg(long, default_value = "8080")]
    port: u16,
}

fn main() {
    let args = Args::parse();
    let target = format!("{}:{}", args.ip, args.port);
    let mut stream = TcpStream::connect(target.as_str()).unwrap();
    println!("Connect to {}", target);
    stream.write_all(b"hello world\n").unwrap();

    let mut buf = [0; 1024];
    let n = stream.read(&mut buf).unwrap();
    println!("client received: {}", String::from_utf8_lossy(&buf[..n]));
}
