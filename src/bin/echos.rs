use std::net::TcpListener;
use std::io::{Read, Write};

fn main() {
    let listener = TcpListener::bind("10.0.0.1:8080").unwrap();
    println!("server listening on 10.0.0.1:8080");

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut buf = [0; 1024];
        let n = stream.read(&mut buf).unwrap();
        stream.write_all(&buf[..n]).unwrap();
    }
}
