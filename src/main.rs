use crate::config::config::load_config;
use crate::proto::proto::{AsciiHandler, get_protocol_handler, register_protocol_handler};
use crate::proto::sse_bin::SseBinaryHandler;
use crate::proto::szse_bin::SzseBinaryHandler;
use crate::{capture::tcp_capture_engine::TcpPcapEngine, tcp::tcp::StreamKey};
use clap::Parser;
use std::vec;
use tokio::task::JoinHandle;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

mod capture;
mod config;
mod proto;
mod record;
mod tcp;
mod util;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Network interface name, e.g. eth0 / lo
    #[arg(long, default_value = "lo")]
    iface: String,

    #[arg(long, default_value = "ASCII")]
    proto: String,

    /// TCP port to filter
    #[arg(long, default_value = "8080")]
    port: u16,

    #[arg(long)]
    config: Option<String>,
}

fn init_tracing() {
    fmt::Subscriber::builder()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("net_tap=info".parse().unwrap()),
        )
        .with_line_number(true)
        .with_file(true)
        .with_target(false)
        .compact()
        .init();
}

fn start_pcap_engine(iface: String, bpf: String, proto: String) -> JoinHandle<()> {
    let handler = get_protocol_handler(proto.as_str()).expect("Protocol handler not found");
    let mut ps = TcpPcapEngine::new(iface, bpf, move |key: StreamKey, data: &[u8]| {
        info!("{} rev \n{}", key, util::hex::to_hex_str_veiw(data));
        handler.on_data(key, data);
    });
    tokio::spawn(async move {
        let _ = ps.start();
    })
}

#[tokio::main]
async fn main() {
    init_tracing();
    register_protocol_handler(AsciiHandler::default());
    register_protocol_handler(SseBinaryHandler::default());
    register_protocol_handler(SzseBinaryHandler::default());
    let args = Args::parse();

    if let Some(config) = args.config {
        let config = load_config(config.as_str()).expect("load config file failed.");
        let mut results = Vec::new();
        for channel in config.channels {
            results.push(start_pcap_engine(channel.iface, channel.bpf, channel.proto));
        }
        for result in results {
            result.await;
        }
    } else {
        start_pcap_engine(args.iface, format!("tcp port {}", args.port), args.proto).await;
    }
}
