use hickory_proto::{op::Message, serialize::binary::BinDecodable};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};

use super::TransportConfig;
use crate::error::{Error, Result};

/// DNS over TCP uses a 2-byte big-endian length prefix (RFC 1035 §4.2.2).
pub async fn send(cfg: &TransportConfig, query: &Message) -> Result<Message> {
    let wire = query.to_vec()?;
    let addr = format!("{}:{}", cfg.server, cfg.port);
    let timeout = std::time::Duration::from_millis(cfg.timeout_ms);

    let mut stream = time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport(format!("connect {addr}: {e}")))?;

    let len = (wire.len() as u16).to_be_bytes();
    time::timeout(timeout, async {
        stream.write_all(&len).await?;
        stream.write_all(&wire).await
    })
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Transport(e.to_string()))?;

    let mut len_buf = [0u8; 2];
    time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport(e.to_string()))?;

    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    time::timeout(timeout, stream.read_exact(&mut resp_buf))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport(e.to_string()))?;

    Ok(Message::from_bytes(&resp_buf)?)
}
