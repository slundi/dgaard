use hickory_proto::{op::Message, serialize::binary::BinDecodable};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};
use tokio_rustls::TlsConnector;

use super::{TransportConfig, tls_config};
use crate::error::{Error, Result};

const ALPN_DOT: &[u8] = b"dot";

/// DNS over TLS (DoT) — RFC 7858.
///
/// Same 2-byte length-prefix framing as plain TCP, wrapped in TLS. Advertises
/// ALPN token `dot` per RFC 7858 §3.2.
pub async fn send(cfg: &TransportConfig, query: &Message) -> Result<Message> {
    let bytes = send_raw(cfg, query).await?;
    Ok(Message::from_bytes(&bytes)?)
}

pub async fn send_raw(cfg: &TransportConfig, query: &Message) -> Result<Vec<u8>> {
    let wire = query.to_vec()?;
    let addr = format!("{}:{}", cfg.server, cfg.port);
    let timeout = std::time::Duration::from_millis(cfg.timeout_ms);

    let tcp = time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport(format!("connect {addr}: {e}")))?;

    let tls_cfg = tls_config::build_client_config(&cfg.tls, &[ALPN_DOT])?;
    let connector = TlsConnector::from(tls_cfg);
    let server_name = tls_config::server_name(&cfg.tls, &cfg.server)?;

    let mut stream = time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport(format!("TLS handshake: {e}")))?;

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

    Ok(resp_buf)
}
