use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use pcap::{Capture, Device};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
};
use pnet_packet::{Packet, tcp::TcpPacket};
use tokio::sync::mpsc;
use tracing::info;

use crate::{
    proto::proto::{DecodedFrame, FrameDecoder},
    record::types::CaptureRecord,
};

mod proto;
mod record;
mod util;
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Network interface name, e.g. eth0 / lo
    #[arg(long, default_value = "lo")]
    iface: String,

    #[arg(long, default_value = "ascii")]
    proto: String,

    /// TCP port to filter
    #[arg(long, default_value = "8080")]
    port: u16,
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
                match msg {
                    DecodedFrame::Ascii(s) => info!("ASCII: {}", s),
                    DecodedFrame::Sse(bin) => info!("SSE: {:?}", bin),
                }
            }
        }
    }
}

#[tokio::main]

async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let dev = Device::list()
        .unwrap()
        .into_iter()
        .find(|d| d.name == args.iface)
        .expect(format!("{} not found", args.iface).as_str());

    info!("Using device: {}", dev.name);

    let (tx, rx) = mpsc::channel::<CaptureRecord>(4096);

    tokio::spawn(async move {
        record::data_record::run_file_writer(rx, "record_data.bin").await;
    });

    let mut cap = Capture::from_device(dev)
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open()
        .unwrap();

    let filter = format!("tcp port {}", args.port);
    cap.filter(&filter, true).unwrap();

    info!("Waiting for packets...");
    let mut frame_decoder = FrameDecoder::new(&args.proto);
    let mut seq = 0;
    while let Ok(packet) = cap.next_packet() {
        let data = packet.data;
        info!("Captured {} bytes", data.len());

        seq += 1;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let rec = CaptureRecord {
            ts_nanos: ts,
            iface: args.iface.clone(),
            seq,
            data: packet.data.to_vec(),
        };

        // 异步写入队列
        if tx.send(rec).await.is_err() {
            eprintln!("Writer exited");
            break;
        }

        info!("\n{}", util::hex::to_hex_str_veiw(data));
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
