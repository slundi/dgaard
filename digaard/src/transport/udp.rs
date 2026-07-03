use hickory_proto::{op::Message, serialize::binary::BinDecodable};
use tokio::{net::UdpSocket, time};

use super::TransportConfig;
use crate::error::{Error, Result};

const UDP_BUF: usize = 4096;

pub async fn send(cfg: &TransportConfig, query: &Message) -> Result<Message> {
    let wire = send_raw(cfg, query).await?;
    let msg = Message::from_bytes(&wire)?;
    if msg.metadata.truncation {
        return Err(Error::Truncated);
    }
    Ok(msg)
}

pub async fn send_raw(cfg: &TransportConfig, query: &Message) -> Result<Vec<u8>> {
    let wire = query.to_vec()?;

    let local = match (cfg.ipv4_only, cfg.ipv6_only) {
        (true, true) => {
            return Err(Error::Transport(
                "-4 and -6 are mutually exclusive".to_string(),
            ));
        }
        (_, true) => "[::]:0",
        _ => "0.0.0.0:0",
    };
    let sock = UdpSocket::bind(local).await?;

    let addr = format!("{}:{}", cfg.server, cfg.port);
    sock.connect(&addr)
        .await
        .map_err(|e| Error::Transport(format!("connect {addr}: {e}")))?;

    let timeout = std::time::Duration::from_millis(cfg.timeout_ms);

    // One initial attempt + `retry` retries. `retry = 0` means single-shot.
    let attempts = cfg.retry.saturating_add(1);
    let mut last_err: Option<Error> = None;

    for attempt in 0..attempts {
        match exchange_once(&sock, &wire, timeout).await {
            Ok(bytes) => return Ok(bytes),
            Err(Error::Timeout) => {
                if attempt + 1 < attempts {
                    log::debug!(
                        "udp timeout (attempt {}/{}), retrying",
                        attempt + 1,
                        attempts
                    );
                }
                last_err = Some(Error::Timeout);
                continue;
            }
            Err(other) => return Err(other),
        }
    }

    Err(last_err.unwrap_or(Error::Timeout))
}

async fn exchange_once(
    sock: &UdpSocket,
    wire: &[u8],
    timeout: std::time::Duration,
) -> Result<Vec<u8>> {
    time::timeout(timeout, sock.send(wire))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport(e.to_string()))?;

    let mut buf = vec![0u8; UDP_BUF];
    let n = time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport(e.to_string()))?;

    buf.truncate(n);
    Ok(buf)
}
