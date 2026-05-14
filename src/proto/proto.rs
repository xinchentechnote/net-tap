use crate::tcp::tcp::StreamKey;
use bytes::{BytesMut};
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

pub fn register_protocol_handler(proto: impl AppProtocolHandler + 'static) {
    let mut map = PROTOCOLS.write().unwrap();
    map.insert(proto.name().to_string(), Arc::new(proto));
}

pub fn get_protocol_handler(name: &str) -> Option<Arc<dyn AppProtocolHandler>> {
    let map = PROTOCOLS.read().unwrap();
    map.get(name).cloned()
}

pub struct AsciiHandler {
    pub buffer_size: usize,
    pub streams: Mutex<HashMap<StreamKey, AsciiDecoder>>,
}

impl AsciiHandler {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            buffer_size,
            streams: Mutex::new(HashMap::new()),
        }
    }

    pub fn default() -> Self {
        Self::new(1024)
    }
}
impl AppProtocolHandler for AsciiHandler {
    fn name(&self) -> &'static str {
        "ASCII"
    }

    fn on_data(&self, key: StreamKey, data: &[u8]) {
        let mut streams = self.streams.lock().unwrap();
        let codec = streams.entry(key.clone()).or_insert_with(|| AsciiDecoder {
            buffer: BytesMut::with_capacity(self.buffer_size),
        });
        codec.feed(data);
        while let Some(msg) = codec.decode_frame() {
            info!("{} rev ASCII: {}", key, msg);
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
