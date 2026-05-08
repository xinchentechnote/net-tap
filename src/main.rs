use clap::Parser;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};
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


fn init_tracing() {
    fmt::Subscriber::builder()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("net_tap=info".parse().unwrap()),
        )
        .with_line_number(true)
        .with_file(true)
        .with_target(false)
        .compact()
        .init();
}


pub fn on_stream_packet(key: StreamKey, data: &[u8]) {
    info!("{} rev \n{}", key, util::hex::to_hex_str_veiw(data))
}

#[tokio::main]

async fn main() {
    init_tracing();
    let args = Args::parse();
    let mut ps = TcpPcapEngine::new(
        args.iface,
        format!("tcp port {}", args.port),
        on_stream_packet,
    );
    let _ = ps.start();
}
