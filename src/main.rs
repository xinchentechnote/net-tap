use pcap::{Capture};

fn main() {
    let mut cap = Capture::from_device("any")
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .open()
        .expect("Failed to open capture");

    cap.filter("tcp port 8080", true).unwrap();

    println!("Waiting for packets...");
    while let Ok(packet) = cap.next_packet() {
        println!("Captured packet, {} bytes", packet.data.len());
    }
}
