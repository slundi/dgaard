use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

pub type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Empty<Bytes>,
>;

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
        .header("User-Agent", "list-stats/0.1")
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
    #[test]
    fn fetch_returns_error_on_bad_uri() {
        // Parsing "not a url" as a hyper::Uri should fail
        let result: Result<hyper::Uri, _> = "not a url".parse();
        assert!(result.is_err());
    }
}
