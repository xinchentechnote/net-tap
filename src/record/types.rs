use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct CaptureRecord {
    pub ts_nanos: u64,
    pub iface: String,
    pub seq: u64,
    pub data: Vec<u8>,
}
