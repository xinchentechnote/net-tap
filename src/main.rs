use binary_codec::BinaryCodec;
use bytes::{Buf, BytesMut};
use clap::Parser;
use pcap::{Capture, Device};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
};
use pnet_packet::{Packet, tcp::TcpPacket};
use sse_binary::sse_binary::SseBinary;
use tracing::info;

mod util;
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Network interface name, e.g. eth0 / lo
    #[arg(short, long, default_value = "lo")]
    iface: String,

    #[arg(short, long, default_value = "txt")]
    proto: String,

    /// TCP port to filter
    #[arg(short, long, default_value = "8080")]
    port: u16,
}

pub struct FrameDecoder {
    buffer: BytesMut,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(4096),
        }
    }
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn next_frame(&mut self) -> Option<SseBinary> {
        if self.buffer.len() < 16 {
            return None;
        }

        let mut header = &self.buffer[..16];
        let _msg_type = header.get_u32();
        let _msg_seq_num = header.get_u64();
        let msg_body_len = header.get_u32() as usize;

        let total_len = 16 + msg_body_len + 4;

        if self.buffer.len() < total_len {
            return None;
        }

        let msg_bytes = self.buffer.split_to(total_len).freeze();

        let mut msg_buf = msg_bytes.clone();
        SseBinary::decode(&mut msg_buf)
    }
}

fn process_ip_packet<P: pnet_packet::Packet>(
    ip_packet: &P,
    src_ip: String,
    dst_ip: String,
    frame_decoder: &mut FrameDecoder,
) {
    let payload = ip_packet.payload();

    if let Some(tcp) = TcpPacket::new(payload) {
        let src_port = tcp.get_source();
        let dst_port = tcp.get_destination();
        let payload = tcp.payload();

        info!(
            "TCP packet: {}:{} -> {}:{}",
            src_ip, src_port, dst_ip, dst_port
        );

        if !payload.is_empty() {
            frame_decoder.feed(payload);
            while let Some(msg) = frame_decoder.next_frame() {
                info!("Payload : {:?}", msg);
            }
        }
    }
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let dev = Device::list()
        .unwrap()
        .into_iter()
        .find(|d| d.name == args.iface)
        .expect(format!("{} not found", args.iface).as_str());

    info!("Using device: {}", dev.name);

    let mut cap = Capture::from_device(dev)
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open()
        .unwrap();

    let filter = format!("tcp port {}", args.port);
    cap.filter(&filter, true).unwrap();

    info!("Waiting for packets...");
    let mut frame_decoder = FrameDecoder::new();
    while let Ok(packet) = cap.next_packet() {
        let data = packet.data;
        info!("Captured {} bytes", data.len());
        info!("\n{}", util::hex::to_hex_string(data));
        let ethernet = EthernetPacket::new(data);
        match ethernet {
            Some(ep) => match ep.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(ep.payload()) {
                        process_ip_packet(
                            &ipv4,
                            ipv4.get_source().to_string(),
                            ipv4.get_destination().to_string(),
                            &mut frame_decoder,
                        );
                    }
                }
                EtherTypes::Ipv6 => {
                    continue;
                }
                _ => {
                    continue;
                }
            },
            None => {
                continue;
            }
        }
    }
}
