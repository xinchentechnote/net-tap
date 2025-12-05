use std::net::TcpStream;
use std::io::{Read, Write};

fn main() {
    let mut stream = TcpStream::connect("10.0.0.1:8080").unwrap();
    stream.write_all(b"hello-tun").unwrap();

    let mut buf = [0; 1024];
    let n = stream.read(&mut buf).unwrap();
    println!("client received: {}", String::from_utf8_lossy(&buf[..n]));
}
