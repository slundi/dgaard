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
        .header("User-Agent", "dgaard/0.1")
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
