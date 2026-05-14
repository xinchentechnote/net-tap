use std::time::{SystemTime, UNIX_EPOCH};

use crate::record::types::CaptureRecord;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::info;

pub fn record_packet(tx: &Sender<CaptureRecord>, device: String, data: &[u8]) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let rec = CaptureRecord {
        ts_nanos: ts,
        iface: device,
        data: data.to_vec(),
    };
    info!("Recording packet {:?}", rec);
    // 异步写入队列
    let _ = tx.send(rec);
}

pub async fn run_file_writer(mut rx: Receiver<CaptureRecord>, path: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .unwrap();
    info!("create  file {:?}", file);
    while let Some(rec) = rx.recv().await {
        info!("record: {:?}", rec);
        let json = serde_json::to_vec(&rec).unwrap();
        let len = json.len() as u32;

        file.write_all(&len.to_le_bytes()).await.unwrap();
        file.write_all(&json).await.unwrap();
    }
}
