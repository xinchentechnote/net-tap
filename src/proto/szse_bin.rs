use crate::proto::proto::{AppProtocolHandler, Decoder};
use crate::tcp::tcp::StreamKey;
use binary_codec::BinaryCodec;
use bytes::{Buf, BytesMut};
use std::collections::HashMap;
use std::sync::Mutex;
use szse_binary::szse_binary::SzseBinary;
use tracing::info;

pub struct SzseBinaryHandler {
    pub buffer_size: usize,
    pub streams: Mutex<HashMap<StreamKey, SzseBinaryDecoder>>,
}

impl SzseBinaryHandler {
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

impl AppProtocolHandler for SzseBinaryHandler {
    fn name(&self) -> &'static str {
        "szse"
    }

    fn on_data(&self, key: StreamKey, data: &[u8]) {
        let mut streams = self.streams.lock().unwrap();
        let codec = streams
            .entry(key.clone())
            .or_insert_with(|| SzseBinaryDecoder {
                buffer: BytesMut::with_capacity(self.buffer_size),
            });
        codec.feed(data);
        while let Some(msg) = codec.decode_frame() {
            info!("{} rev szse binary data: {:?}", key, msg);
        }
    }
}

pub struct SzseBinaryDecoder {
    pub buffer: BytesMut,
}

impl Decoder for SzseBinaryDecoder {
    type Output = SzseBinary;
    fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    fn decode_frame(&mut self) -> Option<Self::Output> {
        if self.buffer.len() < 8 {
            return None;
        }

        let mut header = &self.buffer[..8];
        let _msg_type = header.get_u32();
        let msg_body_len = header.get_u32() as usize;

        let total_len = 8 + msg_body_len + 4;

        if self.buffer.len() < total_len {
            return None;
        }

        let frame = self.buffer.split_to(total_len).freeze();
        let mut buf = frame.clone();

        SzseBinary::decode(&mut buf)
    }
}
