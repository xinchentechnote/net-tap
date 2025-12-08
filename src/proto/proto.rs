use binary_codec::BinaryCodec;
use bytes::{Buf, BytesMut};
use sse_binary::sse_binary::SseBinary;
#[derive(Debug)]
pub enum DecodedFrame {
    Ascii(String),
    Sse(SseBinary),
}

pub enum DecoderType {
    Ascii(AsciiDecoder),
    Sse(SseBinaryDecoder),
}

pub struct FrameDecoder {
    buffer: BytesMut,
    decoder: DecoderType,
}

impl FrameDecoder {
    pub fn new(proto: &str) -> Self {
        let decoder = match proto {
            "sse" => DecoderType::Sse(SseBinaryDecoder),
            "ascii" => DecoderType::Ascii(AsciiDecoder),
            _ => DecoderType::Ascii(AsciiDecoder),
        };

        Self {
            buffer: BytesMut::with_capacity(4096),
            decoder,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn next_frame(&mut self) -> Option<DecodedFrame> {
        match &self.decoder {
            DecoderType::Ascii(decoder) => decoder
                .decode_frame(&mut self.buffer)
                .map(DecodedFrame::Ascii),

            DecoderType::Sse(decoder) => decoder
                .decode_frame(&mut self.buffer)
                .map(DecodedFrame::Sse),
        }
    }
}

pub trait ProtocolDecoder {
    type Output;

    fn decode_frame(&self, buffer: &mut BytesMut) -> Option<Self::Output>;
}
pub struct AsciiDecoder;

impl ProtocolDecoder for AsciiDecoder {
    type Output = String;

    fn decode_frame(&self, buffer: &mut BytesMut) -> Option<Self::Output> {
        if let Some(pos) = buffer.iter().position(|b| *b == b'\n') {
            let line = buffer.split_to(pos + 1);
            return Some(String::from_utf8_lossy(&line).trim().to_string());
        }
        None
    }
}

pub struct SseBinaryDecoder;

impl ProtocolDecoder for SseBinaryDecoder {
    type Output = SseBinary;

    fn decode_frame(&self, buffer: &mut BytesMut) -> Option<Self::Output> {
        if buffer.len() < 16 {
            return None;
        }

        let mut header = &buffer[..16];
        let _msg_type = header.get_u32();
        let _msg_seq_num = header.get_u64();
        let msg_body_len = header.get_u32() as usize;

        let total_len = 16 + msg_body_len + 4;

        if buffer.len() < total_len {
            return None;
        }

        let frame = buffer.split_to(total_len).freeze();
        let mut buf = frame.clone();

        SseBinary::decode(&mut buf)
    }
}
