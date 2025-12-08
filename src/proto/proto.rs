use binary_codec::BinaryCodec;
use bytes::{Buf, BytesMut};
use sse_binary::sse_binary::SseBinary;

pub struct FrameDecoder {
    buffer: BytesMut,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(4096),
        }
    }
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn next_frame(&mut self) -> Option<SseBinary> {
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

        let msg_bytes = self.buffer.split_to(total_len).freeze();

        let mut msg_buf = msg_bytes.clone();
        SseBinary::decode(&mut msg_buf)
    }
}
