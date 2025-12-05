use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let msg = b"hello from client";
    println!("Connecting to echo server 10.0.0.1:8080...");
    let mut stream = TcpStream::connect("10.0.0.1:8080").expect("failed to connect");
    println!("Sending: {}", String::from_utf8_lossy(msg));
    stream.write_all(msg).expect("write failed");

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).expect("read failed");
    println!("Received echo: {}", String::from_utf8_lossy(&buf[..n]));
}
