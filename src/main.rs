use pcap::{Capture, Device};

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

    cap.filter("tcp port 8080", true).unwrap();

    println!("Waiting for packets...");

    while let Ok(packet) = cap.next_packet() {
        let data = packet.data;
        println!("Captured {} bytes", data.len());

        // lo 使用 Linux SLL header: 16 bytes
        if data.len() < 16 + 20 + 20 {
            continue;
        }

        let sll_len = 16;

        // ----- Parse IP header -----
        let ihl = (data[sll_len] & 0x0F) as usize;
        let ip_header_len = ihl * 4;

        // IPv4 only
        if data[sll_len] >> 4 != 4 {
            continue;
        }

        // ----- Parse TCP header -----
        let tcp_offset_pos = sll_len + ip_header_len + 12;
        if tcp_offset_pos >= data.len() {
            continue;
        }
        let data_offset = ((data[tcp_offset_pos] >> 4) & 0x0F) as usize;
        let tcp_header_len = data_offset * 4;

        // ----- Payload -----
        let payload_offset = sll_len + ip_header_len + tcp_header_len;

        if payload_offset >= data.len() {
            continue;
        }

        let payload = &data[payload_offset..];

        if !payload.is_empty() {
            println!("Payload ({} bytes): {:?}", payload.len(), payload);
            println!("ASCII: {}", String::from_utf8_lossy(payload));
        }
    }
}
