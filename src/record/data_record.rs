use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::Receiver;

use crate::record::types::CaptureRecord;

pub async fn run_file_writer(mut rx: Receiver<CaptureRecord>, path: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .unwrap();

    while let Some(rec) = rx.recv().await {
        let json = serde_json::to_vec(&rec).unwrap();
        let len = json.len() as u32;

        file.write_all(&len.to_le_bytes()).await.unwrap();
        file.write_all(&json).await.unwrap();
    }
}
