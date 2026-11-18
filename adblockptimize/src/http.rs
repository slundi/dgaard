use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use url::Url;

pub type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Empty<Bytes>,
>;

/// Create an HTTPS client with rustls for downloading lists.
pub(crate) fn build_https_client() -> HttpsClient {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// Sent with every download: this tool and its real version, so list
/// maintainers can tell clients apart (it used to claim `dgaard/0.1`).
pub(crate) const USER_AGENT: &str = concat!("adblockptimize/", env!("CARGO_PKG_VERSION"));

/// Maximum response body size accepted when downloading a list (50 MiB).
const MAX_RESPONSE_SIZE: usize = 50 * 1024 * 1024;

/// Download a list from a URL using the provided HTTP client.
pub async fn download_list(
    client: &HttpsClient,
    url: &Url,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let uri: hyper::Uri = url.as_str().parse()?;
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .header("User-Agent", USER_AGENT)
        .body(Empty::<Bytes>::new())?;

    let res = client.request(req).await?;
    let status = res.status();
    if !status.is_success() {
        return Err(format!("HTTP error: {}", status).into());
    }

    // Reject early when the server advertises an oversized body.
    if let Some(cl) = res.headers().get(hyper::header::CONTENT_LENGTH)
        && let Ok(len) = cl.to_str().unwrap_or("").parse::<usize>()
        && len > MAX_RESPONSE_SIZE
    {
        return Err(
            format!("Content-Length {len} exceeds limit of {MAX_RESPONSE_SIZE} bytes").into(),
        );
    }

    // Stream the body frame by frame so a large payload never fully materialises.
    let mut body = res.into_body();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Some(data) = frame?.data_ref() {
            buf.extend_from_slice(data);
            if buf.len() > MAX_RESPONSE_SIZE {
                return Err(
                    format!("Response body exceeded limit of {MAX_RESPONSE_SIZE} bytes").into(),
                );
            }
        }
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One-shot HTTP server on 127.0.0.1: answers `body` to the first
    /// request and hands back the raw request it received.
    fn serve_once(body: &'static str) -> (Url, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!(
            "http://{}/list.txt",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            String::from_utf8_lossy(&request).into_owned()
        });
        (url, server)
    }

    #[test]
    fn user_agent_names_this_tool_and_its_version() {
        // it used to send a frozen "dgaard/0.1".
        assert_eq!(
            USER_AGENT,
            format!("adblockptimize/{}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[tokio::test]
    async fn download_sends_the_user_agent_on_the_wire() {
        let (url, server) = serve_once("example.com\n");
        let body = download_list(&build_https_client(), &url).await.unwrap();
        assert_eq!(body, "example.com\n");

        let request = server.join().unwrap().to_ascii_lowercase();
        let expected = format!("user-agent: {USER_AGENT}").to_ascii_lowercase();
        assert!(request.contains(&expected), "{request}");
        assert!(!request.contains("dgaard/0.1"), "{request}");
    }
}
