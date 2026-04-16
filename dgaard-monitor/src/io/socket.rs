use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

use crate::error::MonitorError;
use crate::protocol::StatMessage;

pub fn connect(path: &str) -> Result<UnixStream, MonitorError> {
    // UnixStream::connect is async; use std for sync connect then convert
    // We use a blocking connect via std and then convert.
    // Actually, for the main loop we want to call this from an async context.
    // We'll provide both sync and async variants — the main.rs uses this in an async context.
    // Use std::os::unix::net::UnixStream and convert.
    let std_stream = std::os::unix::net::UnixStream::connect(path)
        .map_err(|e| MonitorError::SocketError(format!("connect to {path}: {e}")))?;
    std_stream
        .set_nonblocking(true)
        .map_err(|e| MonitorError::SocketError(format!("set_nonblocking: {e}")))?;
    UnixStream::from_std(std_stream)
        .map_err(|e| MonitorError::SocketError(format!("from_std: {e}")))
}

pub async fn read_frame(stream: &mut UnixStream) -> Result<StatMessage, MonitorError> {
    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_le_bytes(len_buf) as usize;

    // Read the rest of the frame (msg_len bytes: type + payload)
    let mut payload_buf = vec![0u8; msg_len];
    stream.read_exact(&mut payload_buf).await?;

    // Reconstruct full frame for deserializer: [len: 2][type+payload: msg_len]
    let mut frame = Vec::with_capacity(2 + msg_len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&payload_buf);

    StatMessage::deserialize(&frame)
        .ok_or_else(|| MonitorError::InvalidMessage("failed to deserialize frame".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{StatAction, StatBlockReason, StatEvent};
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;

    async fn make_connected_pair() -> (UnixStream, UnixStream) {
        use std::sync::OnceLock;
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
        let dir = DIR.get_or_init(|| tempfile::tempdir().unwrap());
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.path().join(format!("test_{id}.sock"));

        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn test_read_domain_mapping_frame() {
        let (client, mut server) = make_connected_pair().await;

        let msg = StatMessage::DomainMapping {
            hash: 0xdeadbeef,
            domain: "example.com".to_string(),
        };
        let bytes = msg.serialize();
        server.write_all(&bytes).await.unwrap();
        drop(server);

        let mut stream = client;
        let decoded = read_frame(&mut stream).await.unwrap();
        assert_eq!(decoded, msg);
    }

    #[tokio::test]
    async fn test_read_event_frame() {
        let (client, mut server) = make_connected_pair().await;

        let event = StatEvent {
            timestamp: 12345,
            domain_hash: 0xabcdef,
            client_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            action: StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST),
        };
        let msg = StatMessage::Event(event);
        let bytes = msg.serialize();
        server.write_all(&bytes).await.unwrap();
        drop(server);

        let mut stream = client;
        let decoded = read_frame(&mut stream).await.unwrap();
        assert_eq!(decoded, msg);
    }

    #[tokio::test]
    async fn test_truncated_frame_returns_error() {
        let (client, mut server) = make_connected_pair().await;

        // Write only the length prefix, then close — payload will be missing
        let len: u16 = 10;
        server.write_all(&len.to_le_bytes()).await.unwrap();
        drop(server); // EOF before payload

        let mut stream = client;
        let result = read_frame(&mut stream).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_garbage_frame_returns_error() {
        let (client, mut server) = make_connected_pair().await;

        // Send a frame that has a valid length but garbage type (0xFF)
        let payload: &[u8] = &[0xFF; 5]; // 5 bytes: invalid type + garbage
        let msg_len = payload.len() as u16;
        server.write_all(&msg_len.to_le_bytes()).await.unwrap();
        server.write_all(payload).await.unwrap();
        drop(server);

        let mut stream = client;
        let result = read_frame(&mut stream).await;
        assert!(result.is_err());
    }
}
