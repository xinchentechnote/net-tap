use crate::tcp::tcp::StreamKey;
use binary_codec::BinaryCodec;
use bytes::{Buf, BytesMut};
use sse_binary::sse_binary::SseBinary;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use tracing::info;

pub trait AppProtocolHandler: Send + Sync {
    /// 协议名
    fn name(&self) -> &'static str;

    /// 处理一个 TCP 流方向的数据
    fn on_data(&self, key: StreamKey, data: &[u8]);
}

lazy_static::lazy_static! {
    static ref PROTOCOLS: RwLock<HashMap<String, Arc<dyn AppProtocolHandler>>> =
        RwLock::new(HashMap::new());
}

pub fn register_protocol_Handler(proto: impl AppProtocolHandler + 'static) {
    let mut map = PROTOCOLS.write().unwrap();
    map.insert(proto.name().to_string(), Arc::new(proto));
}

pub fn get_protocol_handler(name: &str) -> Option<Arc<dyn AppProtocolHandler>> {
    let map = PROTOCOLS.read().unwrap();
    map.get(name).cloned()
}

pub struct AsciiHandler {
    pub codec: Mutex<AsciiDecoder>,
}
impl AppProtocolHandler for AsciiHandler {
    fn name(&self) -> &'static str {
        "ASCII"
    }

    fn on_data(&self, key: StreamKey, data: &[u8]) {
        let mut codec = self.codec.lock().unwrap();
        codec.feed(data);
        while let Some(msg) = codec.decode_frame() {
            info!("{} rev ASCII: {}", key, msg);
        }
    }
}

pub struct SseBinaryHandler {
    pub codec: Mutex<SseBinaryDecoder>,
}

impl AppProtocolHandler for SseBinaryHandler {
    fn name(&self) -> &'static str {
        "sse"
    }

    fn on_data(&self, key: StreamKey, data: &[u8]) {
        let mut codec = self.codec.lock().unwrap();
        codec.feed(data);
        while let Some(msg) = codec.decode_frame() {
            info!("{} rev sse binary data: {:?}", key, msg);
        }
    }
}

pub trait ProtocolDecoder {
    type Output;
    fn feed(&mut self, data: &[u8]);
    fn decode_frame(&mut self) -> Option<Self::Output>;
}
pub struct AsciiDecoder {
    pub buffer: BytesMut,
}

impl ProtocolDecoder for AsciiDecoder {
    type Output = String;
    fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    fn decode_frame(&mut self) -> Option<Self::Output> {
        if let Some(pos) = self.buffer.iter().position(|b| *b == b'\n') {
            let line = self.buffer.split_to(pos + 1);
            return Some(String::from_utf8_lossy(&line).trim().to_string());
        }
        None
    }
}

pub struct SseBinaryDecoder {
    pub buffer: BytesMut,
}

impl ProtocolDecoder for SseBinaryDecoder {
    type Output = SseBinary;
    fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    fn decode_frame(&mut self) -> Option<Self::Output> {
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

        let frame = self.buffer.split_to(total_len).freeze();
        let mut buf = frame.clone();

        SseBinary::decode(&mut buf)
    }
}
