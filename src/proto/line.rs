use crate::proto::proto::{AppProtocolHandler, Decoder};
use crate::tcp::tcp::StreamKey;
use bytes::BytesMut;
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::info;

pub struct LineHandler {
    pub buffer_size: usize,
    pub streams: Mutex<HashMap<StreamKey, LineDecoder>>,
}

impl LineHandler {
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

impl AppProtocolHandler for LineHandler {
    fn name(&self) -> &'static str {
        "line"
    }

    fn on_data(&self, key: StreamKey, data: &[u8]) {
        let mut streams = self.streams.lock().unwrap();
        let codec = streams.entry(key.clone()).or_insert_with(|| LineDecoder {
            buffer: BytesMut::with_capacity(self.buffer_size),
        });
        codec.feed(data);
        while let Some(msg) = codec.decode_frame() {
            info!("{} rev data: {}", key, msg);
        }
    }
}

pub struct LineDecoder {
    pub buffer: BytesMut,
}

impl Decoder for LineDecoder {
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
