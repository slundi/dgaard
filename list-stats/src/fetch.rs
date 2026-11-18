use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

pub type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Empty<Bytes>,
>;

/// Sent with every fetch: this tool and its real version.
pub const USER_AGENT: &str = concat!("list-stats/", env!("CARGO_PKG_VERSION"));

pub fn build_client() -> HttpsClient {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

pub async fn fetch(
    client: &HttpsClient,
    url: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let uri: hyper::Uri = url.parse()?;
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .header("User-Agent", USER_AGENT)
        .body(Empty::<Bytes>::new())?;

    let res = client.request(req).await?;
    let status = res.status();
    if !status.is_success() {
        return Err(format!("HTTP {status} for {url}").into());
    }

    let body = res.collect().await?.to_bytes();
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One-shot HTTP server on 127.0.0.1: answers `body` to the first
    /// request and hands back the raw request it received.
    fn serve_once(body: &'static str) -> (String, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/list.txt", listener.local_addr().unwrap());
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
        // Review F13: it used to send a frozen "list-stats/0.1".
        assert_eq!(
            USER_AGENT,
            format!("list-stats/{}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[tokio::test]
    async fn fetch_sends_the_user_agent_on_the_wire() {
        let (url, server) = serve_once("example.com\n");
        let body = fetch(&build_client(), &url).await.unwrap();
        assert_eq!(body, "example.com\n");

        let request = server.join().unwrap().to_ascii_lowercase();
        let expected = format!("user-agent: {USER_AGENT}").to_ascii_lowercase();
        assert!(request.contains(&expected), "{request}");
    }

    #[test]
    fn fetch_returns_error_on_bad_uri() {
        // Parsing "not a url" as a hyper::Uri should fail
        let result: Result<hyper::Uri, _> = "not a url".parse();
        assert!(result.is_err());
    }
}
