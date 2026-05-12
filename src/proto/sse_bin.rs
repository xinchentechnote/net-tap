use std::collections::HashMap;
use std::sync::Mutex;
use binary_codec::BinaryCodec;
use bytes::{Buf, BytesMut};
use sse_binary::sse_binary::SseBinary;
use tracing::info;
use crate::proto::proto::{AppProtocolHandler, ProtocolDecoder};
use crate::tcp::tcp::StreamKey;

pub struct SseBinaryHandler {
    pub buffer_size: usize,
    pub streams: Mutex<HashMap<StreamKey, SseBinaryDecoder>>,
}

impl SseBinaryHandler {
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

impl AppProtocolHandler for SseBinaryHandler {
    fn name(&self) -> &'static str {
        "sse"
    }

    fn on_data(&self, key: StreamKey, data: &[u8]) {
        let mut streams = self.streams.lock().unwrap();
        let codec = streams
            .entry(key.clone())
            .or_insert_with(|| SseBinaryDecoder {
                buffer: BytesMut::with_capacity(self.buffer_size),
            });
        codec.feed(data);
        while let Some(msg) = codec.decode_frame() {
            info!("{} rev sse binary data: {:?}", key, msg);
        }
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
