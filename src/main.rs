use clap::Parser;
use tracing::info;

use crate::{capture::tcp_capture_engine::TcpPcapEngine, tcp::tcp::StreamKey};

mod proto;
mod record;
mod tcp;
mod util;
mod capture;

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


pub fn on_stream_packet(key: StreamKey, data: &[u8]) {
    info!("{:?} rev {}", key, util::hex::to_hex_str_veiw(data))
}

#[tokio::main]

async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let mut ps = TcpPcapEngine::new(
        args.iface,
        format!("tcp port {}", args.port),
        on_stream_packet,
    );
    let _ = ps.start();
}
