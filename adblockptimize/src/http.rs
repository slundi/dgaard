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
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

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

    let body = res.collect().await?.to_bytes();
    Ok(String::from_utf8_lossy(&body).into_owned())
}
