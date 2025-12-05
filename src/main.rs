use pcap::Device;

fn main() {
    let dev = Device::list().unwrap()
        .into_iter()
        .find(|d| d.name == "tun0")
        .expect("no tun0 found");

    let mut cap = dev.open().unwrap();
    println!("Waiting for packets...");

    while let Ok(pkt) = cap.next_packet() {
        println!("Captured {} bytes", pkt.data.len());
    }
}
