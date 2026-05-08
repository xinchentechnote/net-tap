use crate::proto::proto::{
    AsciiDecoder, AsciiHandler, SseBinaryDecoder, SseBinaryHandler, get_protocol_handler,
    register_protocol_Handler,
};
use crate::{capture::tcp_capture_engine::TcpPcapEngine, tcp::tcp::StreamKey};
use bytes::BytesMut;
use clap::Parser;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

mod capture;
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

#[tokio::main]

async fn main() {
    init_tracing();
    register_protocol_Handler(AsciiHandler {
        codec: Mutex::new(AsciiDecoder {
            buffer: BytesMut::with_capacity(4096),
        }),
    });
    register_protocol_Handler(SseBinaryHandler {
        codec: Mutex::new(SseBinaryDecoder {
            buffer: BytesMut::with_capacity(4096),
        }),
    });
    let args = Args::parse();
    let mut handler = get_protocol_handler(&args.proto).expect("Protocol handler not found");
    let mut ps = TcpPcapEngine::new(
        args.iface,
        format!("tcp port {}", args.port),
        move |key: StreamKey, data: &[u8]| {
            info!("{} rev \n{}", key, util::hex::to_hex_str_veiw(data));
            handler.on_data(key, data);
        },
    );
    let _ = ps.start();
}
