use pcap::{Capture, Device};

fn main() {
    let device_name = "tap0";
    let device = Device::list()
        .expect("Failed to list devices")
        .into_iter()
        .find(|d| d.name == device_name)
        .expect("Device tap0 not found");

    println!("Using device: {}", device.name);
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .open()
        .expect("Failed to open capture");

    println!("Waiting for packets...");
    while let Ok(packet) = cap.next_packet() {
        println!("Captured packet, {} bytes", packet.data.len());
        println!("Raw: {:?}", packet.data);
    }
}
