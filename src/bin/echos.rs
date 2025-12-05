use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    let listener = TcpListener::bind("10.0.0.2:8080").expect("bind failed");
    loop {
        let (mut socket, _) = listener.accept().expect("accept failed");
        let mut buf = [0u8; 1024];
        let n = socket.read(&mut buf).unwrap_or(0);
        if n > 0 {
            socket.write_all(&buf[..n]).unwrap();
        }
    }
}