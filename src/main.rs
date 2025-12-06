use clap::Parser;
use pcap::{Capture, Device};

mod util;
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Network interface name, e.g. eth0 / lo
    #[arg(short, long, default_value = "lo")]
    iface: String,

    /// TCP port to filter
    #[arg(short, long, default_value = "8080")]
    port: u16,
}

fn main() {
    let args = Args::parse();
    let dev = Device::list()
        .unwrap()
        .into_iter()
        .find(|d| d.name == args.iface)
        .expect(format!("{} not found", args.iface).as_str());

    println!("Using device: {}", dev.name);

    let mut cap = Capture::from_device(dev)
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open()
        .unwrap();

    let filter = format!("tcp port {}", args.port);
    cap.filter(&filter, true).unwrap();

    println!("Waiting for packets...");

    while let Ok(packet) = cap.next_packet() {
        let data = packet.data;
        println!("Captured {} bytes", data.len());
        println!("{}", util::hex::to_hex_string(data));

        // ------------------------
        // Ethernet header is 16 bytes
        // dst mac 6 bytes
        // src mac 6 bytes
        // protocol 2 bytes, ipv4 = 08 00
        // ------------------------
        const ETH_HDR_LEN: usize = 14;

        if data.len() < ETH_HDR_LEN + 20 {
            continue;
        }

        // ------------------------
        // IPv4 header is 20 bytes
        //4 → Version = IPv4
        //5 → IHL = 5 × 4 = 20 bytes header
        // ------------------------
        let ip_start = ETH_HDR_LEN;

        let version = data[ip_start] >> 4;
        println!("version:{}", version);
        if version != 4 {
            continue;
        }

        let ihl = (data[ip_start] & 0x0F) as usize;
        let ip_header_len = ihl * 4;

        if data.len() < ETH_HDR_LEN + ip_header_len + 20 {
            continue;
        }

        // ------------------------
        // Parse TCP header
        // 20 bytes +
        // ------------------------
        let tcp_start = ETH_HDR_LEN + ip_header_len;

        let offset_byte_pos = tcp_start + 12;
        if offset_byte_pos >= data.len() {
            continue;
        }

        let data_offset_words = (data[offset_byte_pos] >> 4) as usize;
        let tcp_header_len = data_offset_words * 4;

        if data.len() < tcp_start + tcp_header_len {
            continue;
        }

        // ------------------------
        // Payload
        // ------------------------
        let payload_offset = tcp_start + tcp_header_len;

        if payload_offset >= data.len() {
            continue;
        }

        let payload = &data[payload_offset..];

        if !payload.is_empty() {
            println!("Payload ({} bytes): {:02x?}", payload.len(), payload);
            println!("ASCII: {}", String::from_utf8_lossy(payload));
        }
    }
}
