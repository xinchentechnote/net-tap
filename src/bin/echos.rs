use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    let listener = TcpListener::bind("10.0.0.1:8080").expect("bind failed");
    println!("Echo server listening on 10.0.0.1:8080");
    for stream in listener.incoming() {
        let mut socket = stream.expect("accept failed");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).unwrap_or(0);
            if n > 0 {
                socket.write_all(&buf[..n]).unwrap();
            }
        });
    }
}
