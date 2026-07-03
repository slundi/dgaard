use hickory_proto::{op::Message, serialize::binary::BinDecodable};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};
use tokio_rustls::TlsConnector;

use super::TransportConfig;
use crate::error::{Error, Result};

/// DNS over TLS (DoT) — RFC 7858.
///
/// Same 2-byte length-prefix framing as plain TCP, wrapped in TLS.
pub async fn send(cfg: &TransportConfig, query: &Message) -> Result<Message> {
    let wire = query.to_vec()?;
    let addr = format!("{}:{}", cfg.server, cfg.port);
    let timeout = std::time::Duration::from_millis(cfg.timeout_ms);

    let tcp = time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport(format!("connect {addr}: {e}")))?;

    let tls_cfg = std::sync::Arc::new(client_tls_config()?);
    let connector = TlsConnector::from(tls_cfg);
    let server_name = rustls::pki_types::ServerName::try_from(cfg.server.as_str())
        .map_err(|e| Error::Transport(format!("invalid server name '{}': {e}", cfg.server)))?
        .to_owned();

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

    Ok(Message::from_bytes(&resp_buf)?)
}

fn client_tls_config() -> Result<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
        .pipe(Ok)
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}
impl<T> Pipe for T {}
