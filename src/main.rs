use pcap::{Capture, Device};

fn main() {
    let device_name = "tun0";
    let device = Device::list()
        .expect("Failed to list devices")
        .into_iter()
        .find(|d| d.name == device_name)
        .expect("Device tun0 not found");

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
        let data = packet.data;
        if !data.is_empty() {
            // TUN 是 L3，payload 从 IP header 后开始
            // 简单打印原始数据
            println!("Payload ({} bytes): {:?}", data.len(), data);
            if data.iter().all(|b| b.is_ascii()) {
                println!("ASCII: {}", String::from_utf8_lossy(data));
            }
        }
    }
}
