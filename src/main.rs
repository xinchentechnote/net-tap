use std::sync::{Arc, Mutex};
use clap::Parser;
use tokio::io::AsyncWriteExt;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};
use crate::{capture::tcp_capture_engine::TcpPcapEngine, tcp::tcp::StreamKey};
use crate::proto::proto::{DecodedFrame, FrameDecoder};

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


#[tokio::main]

async fn main() {
    init_tracing();
    let args = Args::parse();
    let frame_decoder = Arc::new(Mutex::new(
        FrameDecoder::new(args.proto.as_str()),
    ));
    let mut ps = TcpPcapEngine::new(
        args.iface,
        format!("tcp port {}", args.port),
        move |key: StreamKey, data: &[u8]| {
            info!("{} rev \n{}", key, util::hex::to_hex_str_veiw(data));
            frame_decoder.lock().unwrap().feed(data);
            while let Some(msg) = frame_decoder.lock().unwrap().next_frame() {
                match msg {
                    DecodedFrame::Ascii(s) => info!("ASCII: {}", s),
                    DecodedFrame::Sse(bin) => info!("SSE: {:?}", bin),
                }
            }
        },
    );
    let _ = ps.start();
}
