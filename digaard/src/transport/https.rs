use hickory_proto::{op::Message, serialize::binary::BinDecodable};
use hyper::{
    Method, Request,
    body::Bytes,
    header::{ACCEPT, CONTENT_TYPE},
};
use hyper_util::client::legacy::Client;

use super::{DohMethod, TransportConfig, tls_config};
use crate::error::{Error, Result};

const DNS_MSG_TYPE: &str = "application/dns-message";

/// DNS over HTTPS (DoH) — RFC 8484.
pub async fn send(cfg: &TransportConfig, query: &Message) -> Result<Message> {
    let bytes = send_raw(cfg, query).await?;
    Ok(Message::from_bytes(&bytes)?)
}

pub async fn send_raw(cfg: &TransportConfig, query: &Message) -> Result<Vec<u8>> {
    let wire = query.to_vec()?;

    // hyper-rustls sets ALPN itself based on enable_http1/2; pass empty here.
    let tls_cfg = tls_config::build_client_config(&cfg.tls, &[])?;
    let tls = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config((*tls_cfg).clone())
        .https_only()
        .enable_http1()
        .build();

    let client: Client<_, http_body_util::Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build(tls);

    let uri = build_uri(cfg, &wire)?;

    let req = match cfg.doh.method {
        DohMethod::Post => Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(CONTENT_TYPE, DNS_MSG_TYPE)
            .header(ACCEPT, DNS_MSG_TYPE)
            .body(http_body_util::Full::new(Bytes::from(wire)))
            .map_err(|e| Error::Transport(format!("build request: {e}")))?,
        DohMethod::Get => Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(ACCEPT, DNS_MSG_TYPE)
            .body(http_body_util::Full::new(Bytes::new()))
            .map_err(|e| Error::Transport(format!("build request: {e}")))?,
    };

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

    Ok(body.to_vec())
}

fn build_uri(cfg: &TransportConfig, wire: &[u8]) -> Result<hyper::Uri> {
    // Ensure the path starts with '/'; user may have supplied a bare "dns-query".
    let path = if cfg.doh.path.starts_with('/') {
        cfg.doh.path.clone()
    } else {
        format!("/{}", cfg.doh.path)
    };

    let host_part = if cfg.server.contains(':') && !cfg.server.starts_with('[') {
        // Bare IPv6 literal.
        format!("[{}]", cfg.server)
    } else {
        cfg.server.clone()
    };

    let uri_str = match cfg.doh.method {
        DohMethod::Post => format!("https://{host_part}:{port}{path}", port = cfg.port),
        DohMethod::Get => {
            let dns = base64url_nopad(wire);
            format!(
                "https://{host_part}:{port}{path}?dns={dns}",
                port = cfg.port
            )
        }
    };

    uri_str
        .parse::<hyper::Uri>()
        .map_err(|e| Error::Transport(format!("invalid DoH URI '{uri_str}': {e}")))
}

/// Base64url without padding, as required by RFC 8484 §4.1.
fn base64url_nopad(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n =
            (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8) | u32::from(bytes[i + 2]);
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        out.push(CHARS[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        0 => {}
        1 => {
            let n = u32::from(bytes[i]) << 16;
            out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let n = (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8);
            out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => unreachable!(),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{DohMethod, DohSettings, TlsSettings};

    fn cfg(method: DohMethod, path: &str, server: &str, port: u16) -> TransportConfig {
        TransportConfig {
            server: server.to_string(),
            port,
            timeout_ms: 1000,
            retry: 0,
            ipv4_only: false,
            ipv6_only: false,
            tls: TlsSettings::default(),
            doh: DohSettings {
                method,
                path: path.to_string(),
            },
        }
    }

    #[test]
    fn base64url_matches_rfc_4648_examples() {
        // RFC 4648 Table 2 example: "" -> "".
        assert_eq!(base64url_nopad(b""), "");
        // Base64url of "f" is "Zg", "fo" is "Zm8", "foo" is "Zm9v".
        assert_eq!(base64url_nopad(b"f"), "Zg");
        assert_eq!(base64url_nopad(b"fo"), "Zm8");
        assert_eq!(base64url_nopad(b"foo"), "Zm9v");
        // Bytes 0xff twice must produce '_' (byte value 0x3f in the last alphabet slot).
        assert_eq!(base64url_nopad(&[0xff, 0xff]), "__8");
    }

    #[test]
    fn post_uri_uses_path_and_port() {
        let c = cfg(DohMethod::Post, "/dns-query", "dns.example", 443);
        let uri = build_uri(&c, &[]).unwrap();
        assert_eq!(uri.to_string(), "https://dns.example:443/dns-query");
    }

    #[test]
    fn get_uri_encodes_dns_query_param() {
        let c = cfg(DohMethod::Get, "/dns-query", "dns.example", 443);
        let uri = build_uri(&c, &[0x00, 0x01, 0x02]).unwrap();
        assert!(
            uri.to_string()
                .starts_with("https://dns.example:443/dns-query?dns=")
        );
    }

    #[test]
    fn path_without_leading_slash_is_fixed_up() {
        let c = cfg(DohMethod::Post, "dns-query", "dns.example", 443);
        let uri = build_uri(&c, &[]).unwrap();
        assert_eq!(uri.path(), "/dns-query");
    }

    #[test]
    fn ipv6_literal_is_bracketed() {
        let c = cfg(DohMethod::Post, "/dns-query", "2001:db8::1", 443);
        let uri = build_uri(&c, &[]).unwrap();
        assert!(uri.to_string().starts_with("https://[2001:db8::1]:443/"));
    }
}
