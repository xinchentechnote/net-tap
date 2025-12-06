use pcap::Capture;
use pcap::Device;

fn main() {
    let dev = Device::list()
        .unwrap()
        .into_iter()
        .find(|d| d.name == "lo")
        .expect("lo not found");

    println!("Using device: {}", dev.name);

    let mut cap = Capture::from_device(dev)
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open()
        .unwrap();

    println!("Waiting for packets...");

    while let Ok(packet) = cap.next_packet() {
        println!("Captured {} bytes", packet.data.len());
    }
}
