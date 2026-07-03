//! DNS over QUIC (DoQ) — RFC 9250.
//!
//! Semantics (RFC 9250):
//!   - ALPN token: `doq`
//!   - One bidirectional stream per DNS query
//!   - Wire framing: 2-byte big-endian length prefix (same as TCP/DoT)
//!   - Client SHOULD set the message ID to 0 (§4.2.1); QUIC streams already
//!     carry per-transaction identity, so the DNS ID is redundant
//!   - Server closes its send-side after writing the response

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use super::{TransportConfig, tls_config};
use crate::error::{Error, Result};
use hickory_proto::op::Message;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};

const ALPN_DOQ: &[u8] = b"doq";

pub async fn send_raw(cfg: &TransportConfig, query: &Message) -> Result<Vec<u8>> {
    let timeout = std::time::Duration::from_millis(cfg.timeout_ms);
    tokio::time::timeout(timeout, exchange(cfg, query))
        .await
        .map_err(|_| Error::Timeout)?
}

async fn exchange(cfg: &TransportConfig, query: &Message) -> Result<Vec<u8>> {
    // DoQ requires ID = 0 (RFC 9250 §4.2.1). Clone and rewrite before serializing.
    let wire = {
        let mut q = query.clone();
        q.metadata.id = 0;
        q.to_vec()?
    };

    // Resolve server host to a SocketAddr (blocking DNS via std, off the runtime).
    let host = cfg.server.clone();
    let port = cfg.port;
    let addr = tokio::task::spawn_blocking(move || {
        (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| Error::Transport(format!("resolve {host}:{port}: {e}")))
            .and_then(|mut it| {
                it.next()
                    .ok_or_else(|| Error::Transport(format!("no address for {host}:{port}")))
            })
    })
    .await
    .map_err(|e| Error::Transport(format!("resolver join: {e}")))??;

    let endpoint = build_endpoint(cfg, addr)?;
    let server_name_owned = tls_config::server_name(&cfg.tls, &cfg.server)?;
    let server_name = server_name_display(&server_name_owned).to_string();

    let connecting = endpoint
        .connect(addr, &server_name)
        .map_err(|e| Error::Transport(format!("DoQ connect: {e}")))?;
    let connection = connecting
        .await
        .map_err(|e| Error::Transport(format!("DoQ handshake: {e}")))?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| Error::Transport(format!("DoQ open_bi: {e}")))?;

    let len = (wire.len() as u16).to_be_bytes();
    send.write_all(&len)
        .await
        .map_err(|e| Error::Transport(format!("DoQ send len: {e}")))?;
    send.write_all(&wire)
        .await
        .map_err(|e| Error::Transport(format!("DoQ send msg: {e}")))?;
    send.finish()
        .map_err(|e| Error::Transport(format!("DoQ finish: {e}")))?;

    // Read length prefix, then that many bytes.
    let mut len_buf = [0u8; 2];
    read_exact(&mut recv, &mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    read_exact(&mut recv, &mut resp_buf).await?;

    // Politely close the connection and drop the endpoint. We don't await
    // wait_idle() to avoid blocking on the server's CONNECTION_CLOSE ack.
    connection.close(0u32.into(), b"done");
    drop(endpoint);

    Ok(resp_buf)
}

async fn read_exact(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let n = recv
            .read(&mut buf[off..])
            .await
            .map_err(|e| Error::Transport(format!("DoQ read: {e}")))?
            .ok_or_else(|| Error::Transport("DoQ stream closed early".to_string()))?;
        if n == 0 {
            return Err(Error::Transport("DoQ read returned zero".to_string()));
        }
        off += n;
    }
    Ok(())
}

fn build_endpoint(cfg: &TransportConfig, remote: SocketAddr) -> Result<Endpoint> {
    let rustls_cfg = tls_config::build_client_config(&cfg.tls, &[ALPN_DOQ])?;
    let quic_client: QuicClientConfig = (*rustls_cfg)
        .clone()
        .try_into()
        .map_err(|e| Error::Transport(format!("DoQ crypto config: {e}")))?;
    let client_config = QuinnClientConfig::new(Arc::new(quic_client));

    let local = match remote {
        SocketAddr::V4(_) => "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>().unwrap(),
    };

    let mut endpoint =
        Endpoint::client(local).map_err(|e| Error::Transport(format!("DoQ bind {local}: {e}")))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Pull a `&str` view out of `ServerName<'static>`.
///
/// rustls' `ServerName` doesn't expose a direct `&str`, so we round-trip via
/// its Debug — good enough for DNS-name variants; IP variants are rejected by
/// quinn upstream with a clear error.
fn server_name_display(name: &rustls::pki_types::ServerName<'static>) -> String {
    match name {
        rustls::pki_types::ServerName::DnsName(n) => n.as_ref().to_string(),
        rustls::pki_types::ServerName::IpAddress(ip) => format!("{ip:?}"),
        _ => format!("{name:?}"),
    }
}
