use pcap::{Capture, Device};

fn main() {
    let device_name = "lo";
    let device = Device::list()
        .expect("Failed to list devices")
        .into_iter()
        .find(|d| d.name == device_name)
        .expect("Device eth0 not found");
    println!("Using device: {}", device.name);
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .open()
        .expect("Failed to open capture");
    cap.filter("tcp port 8080", true)
        .expect("Failed to set filter");
    println!("Waiting for packets...");
    while let Ok(packet) = cap.next_packet() {
        println!("Captured packet, {} bytes", packet.data.len());
        let data = packet.data;
        if data.len() > 54 {
            // Ethernet(14) + IP(20) + TCP(20) = 54 bytes header
            let payload = &data[54..];
            if !payload.is_empty() {
                println!("Payload ({} bytes): {:?}", payload.len(), payload);
                println!("ASCII: {}", String::from_utf8_lossy(payload));
                if payload.iter().all(|b| b.is_ascii()) {
                    println!("ASCII: {}", String::from_utf8_lossy(payload));
                }
            }
        }
    }
}
