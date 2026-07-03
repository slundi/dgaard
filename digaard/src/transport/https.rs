use hickory_proto::{op::Message, serialize::binary::BinDecodable};
use hyper::{
    Method, Request,
    body::Bytes,
    header::{ACCEPT, CONTENT_TYPE},
};
use hyper_util::client::legacy::Client;

use super::TransportConfig;
use crate::error::{Error, Result};

const DNS_MSG_TYPE: &str = "application/dns-message";
const DOH_PATH: &str = "/dns-query";

/// DNS over HTTPS (DoH) — RFC 8484, POST method.
pub async fn send(cfg: &TransportConfig, query: &Message) -> Result<Message> {
    let wire = query.to_vec()?;

    let tls = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();

    let client: Client<_, http_body_util::Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build(tls);

    let uri = format!("https://{}:{}{DOH_PATH}", cfg.server, cfg.port)
        .parse::<hyper::Uri>()
        .map_err(|e| Error::Transport(format!("invalid DoH URI: {e}")))?;

    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, DNS_MSG_TYPE)
        .header(ACCEPT, DNS_MSG_TYPE)
        .body(http_body_util::Full::new(Bytes::from(wire)))
        .map_err(|e| Error::Transport(format!("build request: {e}")))?;

    let resp = tokio::time::timeout(
        std::time::Duration::from_millis(cfg.timeout_ms),
        client.request(req),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Transport(format!("HTTP request: {e}")))?;

    if !resp.status().is_success() {
        return Err(Error::Transport(format!(
            "DoH server returned HTTP {}",
            resp.status()
        )));
    }

    use http_body_util::BodyExt;
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| Error::Transport(format!("read body: {e}")))?
        .to_bytes();

    Ok(Message::from_bytes(&body)?)
}
