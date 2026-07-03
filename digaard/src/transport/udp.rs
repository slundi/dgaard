use hickory_proto::{op::Message, serialize::binary::BinDecodable};
use tokio::{net::UdpSocket, time};

use super::TransportConfig;
use crate::error::{Error, Result};

const UDP_BUF: usize = 4096;

pub async fn send(cfg: &TransportConfig, query: &Message) -> Result<Message> {
    let wire = query.to_vec()?;

    let local = if cfg.ipv6_only { ":::0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(local).await?;

    let addr = format!("{}:{}", cfg.server, cfg.port);
    sock.connect(&addr)
        .await
        .map_err(|e| Error::Transport(format!("connect {addr}: {e}")))?;

    let timeout = std::time::Duration::from_millis(cfg.timeout_ms);

    time::timeout(timeout, sock.send(&wire))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport(e.to_string()))?;

    let mut buf = vec![0u8; UDP_BUF];
    let n = time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport(e.to_string()))?;

    let response = Message::from_bytes(&buf[..n])?;

    if response.metadata.truncation {
        return Err(Error::Truncated);
    }

    Ok(response)
}
