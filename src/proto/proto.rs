use crate::tcp::tcp::StreamKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

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

pub trait Decoder {
    type Output;
    fn feed(&mut self, data: &[u8]);
    fn decode_frame(&mut self) -> Option<Self::Output>;
}
