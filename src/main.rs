use crate::config::config::load_config;
use crate::proto::proto::{AsciiHandler, get_protocol_handler, register_protocol_handler};
use crate::proto::sse_bin::SseBinaryHandler;
use crate::proto::szse_bin::SzseBinaryHandler;
use crate::{capture::tcp_capture_engine::TcpPcapEngine, tcp::tcp::StreamKey};
use anyhow::Result;
use clap::Parser;
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
    #[arg(long, default_value = "tcp port 8080")]
    bpf: String,

    #[arg(long)]
    config: Option<String>,
    #[arg(long)]
    journal_path: Option<String>,
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

fn start_pcap_engine(
    iface: String,
    bpf: String,
    proto: String,
    journal_path: Option<String>,
) -> JoinHandle<Result<()>> {
    let handler = get_protocol_handler(proto.as_str()).expect("Protocol handler not found");
    let mut ps = TcpPcapEngine::new(iface, bpf, move |key: StreamKey, data: &[u8]| {
        info!("{} rev \n{}", key, util::hex::to_hex_str_veiw(data));
        handler.on_data(key, data);
    });
    ps.journal_path = journal_path;
    tokio::task::spawn(async move { ps.start().await })
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
        info!("config: {:?}", config);
        let mut results = Vec::new();
        for channel in config.channels {
            results.push(start_pcap_engine(
                channel.iface,
                channel.bpf,
                channel.proto,
                channel.journal_path,
            ));
        }
        for result in results {
            let _ = result.await;
        }
    } else {
        let _ = start_pcap_engine(args.iface, args.bpf, args.proto, args.journal_path).await;
    }
}
