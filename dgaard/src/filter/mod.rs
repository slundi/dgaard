pub use dgaard_engine::filter::engine;
pub use dgaard_engine::filter::engine::FilterEngine;
pub use dgaard_engine::filter::host_index;
pub use dgaard_engine::filter::{load_list_file, write_browser_rules};

use dgaard_engine::filter::{LoadFilter, load_list_content};
use dgaard_engine::model::{DomainEntry, DomainEntryFlags};

use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::header::{CONTENT_LENGTH, LOCATION};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use regex::Regex;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex, atomic::Ordering},
};
use url::Url;

use crate::config::Config;
use crate::updater::{Resource, validate_input};
use crate::{CONFIG, CURRENT_ENGINE, GLOBAL_SEED};

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Empty<Bytes>,
>;

type DownloadError = Box<dyn std::error::Error + Send + Sync>;

/// Redirect hops followed before a download is abandoned.
const MAX_REDIRECTS: usize = 5;

pub(crate) fn build_https_client() -> HttpsClient {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // The connector speaks both schemes; `FetchPolicy` decides whether a
    // plain-HTTP URL (or redirect target) may be fetched at all.
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// Download rules for list URLs, from `[sources]`.
#[derive(Debug, Clone, Copy)]
struct FetchPolicy {
    allow_insecure_http: bool,
    max_bytes: usize,
}

impl FetchPolicy {
    fn from_config(cfg: &Config) -> Self {
        Self {
            allow_insecure_http: cfg.sources.allow_insecure_http,
            max_bytes: (cfg.sources.max_list_size_mb as usize).saturating_mul(1024 * 1024),
        }
    }

    fn check_scheme(&self, url: &Url) -> Result<(), DownloadError> {
        match url.scheme() {
            "https" => Ok(()),
            "http" if self.allow_insecure_http => Ok(()),
            "http" => Err(format!(
                "plain HTTP refused for {url} (set sources.allow_insecure_http to allow)"
            )
            .into()),
            other => Err(format!("unsupported scheme {other} for {url}").into()),
        }
    }
}

/// Download one list: HTTPS only (unless allowed), redirects followed under
/// the same scheme rule, body capped at `policy.max_bytes`.
async fn download_list(
    client: &HttpsClient,
    url: &Url,
    policy: FetchPolicy,
) -> Result<String, DownloadError> {
    let mut current = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        policy.check_scheme(&current)?;
        let uri: hyper::Uri = current.as_str().parse()?;
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(&uri)
            .header("User-Agent", concat!("dgaard/", env!("CARGO_PKG_VERSION")))
            .body(Empty::<Bytes>::new())?;

        let res = client.request(req).await?;
        let status = res.status();
        if status.is_redirection() {
            let location = res
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| format!("HTTP {status} without a Location header"))?;
            current = current.join(location)?;
            continue;
        }
        if !status.is_success() {
            return Err(format!("HTTP error: {status}").into());
        }
        let declared = res
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        if declared.is_some_and(|len| len > policy.max_bytes) {
            return Err(format!("list larger than {} bytes", policy.max_bytes).into());
        }
        // Enforced while streaming too: the length may be absent or lie.
        let body = Limited::new(res.into_body(), policy.max_bytes)
            .collect()
            .await
            .map_err(|e| format!("list body refused: {e}"))?
            .to_bytes();
        // Zero-copy when the body is valid UTF-8; lossy replacement otherwise.
        return Ok(match String::from_utf8(body.to_vec()) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        });
    }
    Err(format!("more than {MAX_REDIRECTS} redirects for {url}").into())
}

// ---------------------------------------------------------------------------
// Last valid copy of each URL list
// ---------------------------------------------------------------------------

/// Last valid list per URL when `list_cache_dir` is empty (memory only).
static MEMORY_LAST_GOOD: LazyLock<Mutex<HashMap<String, Arc<str>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Cache file of `source` under `dir`.
fn last_good_path(dir: &Path, source: &str) -> PathBuf {
    let hash = twox_hash::XxHash64::oneshot(0, source.as_bytes());
    dir.join(format!("{hash:016x}.list"))
}

/// Keep `content` as the last valid copy of `source`. The disk copy is
/// replaced atomically (temp file + rename) so a crash never leaves a
/// half-written list behind.
async fn store_last_good(cache_dir: &str, source: &str, content: &str) {
    if cache_dir.is_empty() {
        MEMORY_LAST_GOOD
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(source.to_owned(), Arc::from(content));
        return;
    }
    let dir = PathBuf::from(cache_dir);
    let path = last_good_path(&dir, source);
    let content = content.to_owned();
    // Plain file IO on the blocking pool (tokio's `fs` feature is not
    // pulled in, to keep the binary small).
    let result = tokio::task::spawn_blocking(move || {
        let tmp = path.with_extension("list.tmp");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(&tmp, content)?;
        std::fs::rename(&tmp, &path)
    })
    .await
    .unwrap_or_else(|e| Err(std::io::Error::other(e)));
    if let Err(e) = result {
        eprintln!("Warning: cannot cache {} in {}: {}", source, cache_dir, e);
    }
}

/// The last valid copy of `source`, if any.
async fn load_last_good(cache_dir: &str, source: &str) -> Option<String> {
    if cache_dir.is_empty() {
        return MEMORY_LAST_GOOD
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(source)
            .map(|content| content.to_string());
    }
    let path = last_good_path(Path::new(cache_dir), source);
    tokio::task::spawn_blocking(move || std::fs::read_to_string(path).ok())
        .await
        .ok()
        .flatten()
}

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------

/// What a reload could not get fresh, used to schedule an early retry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReloadReport {
    /// URL sources served from their last valid copy.
    pub stale: Vec<String>,
    /// Sources with no usable content at all (never fetched, unreadable).
    pub missing: Vec<String>,
    /// The reload hit `reload_timeout_secs`; the previous engine is kept.
    pub timed_out: bool,
}

impl ReloadReport {
    /// True when the engine lacks fresh content for at least one source.
    pub fn is_degraded(&self) -> bool {
        !self.stale.is_empty() || !self.missing.is_empty() || self.timed_out
    }
}

/// Content of one configured source, fetched for this reload.
enum SourceContent {
    /// Downloaded (or last valid copy of) a URL list.
    Text(String),
    /// Local file, read while building.
    File(String),
}

/// One source ready to be parsed into the engine.
struct FetchedSource {
    source: String,
    flags: DomainEntryFlags,
    /// Apply the load-time filter (blacklists, NRD; never whitelists).
    filtered: bool,
    content: SourceContent,
}

/// Fetch one source. A failed download falls back to the last valid copy;
/// without one the source is reported missing and left out.
async fn fetch_source(
    source: &str,
    flags: DomainEntryFlags,
    filtered: bool,
    client: &HttpsClient,
    policy: FetchPolicy,
    cache_dir: &str,
    report: &mut ReloadReport,
) -> Option<FetchedSource> {
    let content = match validate_input(source) {
        Ok(Resource::HttpUrl(url)) => match download_list(client, &url, policy).await {
            Ok(content) => {
                println!("Downloaded {} ({} bytes)", source, content.len());
                store_last_good(cache_dir, source, &content).await;
                SourceContent::Text(content)
            }
            Err(e) => match load_last_good(cache_dir, source).await {
                Some(content) => {
                    eprintln!(
                        "Warning: failed to download {}: {} — using its last valid copy",
                        source, e
                    );
                    report.stale.push(source.to_owned());
                    SourceContent::Text(content)
                }
                None => {
                    eprintln!(
                        "Error: failed to download {}: {} — no previous copy, list skipped",
                        source, e
                    );
                    report.missing.push(source.to_owned());
                    return None;
                }
            },
        },
        Ok(Resource::FilePath(_)) => SourceContent::File(source.to_owned()),
        Err(e) => {
            eprintln!("Error: invalid source {}: {}", source, e);
            report.missing.push(source.to_owned());
            return None;
        }
    };
    Some(FetchedSource {
        source: source.to_owned(),
        flags,
        filtered,
        content,
    })
}

/// Everything a build produces besides the engine.
struct BuiltEngine {
    engine: FilterEngine,
    host_index: HashMap<u64, String>,
    browser_rules: Vec<String>,
    /// File sources that could not be read.
    unreadable: Vec<String>,
}

/// Parse every fetched source and assemble the engine.
///
/// CPU-bound (parsing, regex compilation, sorting): runs on the blocking
/// pool so the DNS runtime keeps serving, even with `worker_threads = 1`.
/// Each list's text is dropped as soon as it is parsed to bound the memory
/// peak.
fn build_engine(sources: Vec<FetchedSource>, cfg: &Config, seed: u64) -> BuiltEngine {
    let mut fast_map: HashMap<u64, (u8, Box<str>)> = HashMap::new();
    let mut hierarchical_list: Vec<DomainEntry> = Vec::new();
    let mut regex_pool: Vec<Regex> = Vec::new();
    let mut wildcard_patterns: Vec<String> = Vec::new();
    let mut host_index: HashMap<u64, String> = HashMap::new();
    let mut browser_rules: Vec<String> = Vec::new();
    let mut unreadable = Vec::new();

    let load_filter = LoadFilter::from_config(cfg, seed);

    for fetched in sources {
        let filter = fetched.filtered.then_some(&load_filter);
        match fetched.content {
            SourceContent::Text(content) => load_list_content(
                &content,
                fetched.flags,
                seed,
                &mut fast_map,
                &mut hierarchical_list,
                &mut wildcard_patterns,
                &mut regex_pool,
                &mut host_index,
                &mut browser_rules,
                filter,
            ),
            SourceContent::File(path) => {
                if let Err(e) = load_list_file(
                    &path,
                    fetched.flags,
                    seed,
                    &mut fast_map,
                    &mut hierarchical_list,
                    &mut wildcard_patterns,
                    &mut regex_pool,
                    &mut host_index,
                    &mut browser_rules,
                    filter,
                ) {
                    eprintln!("Error: failed to load {}: {}", fetched.source, e);
                    unreadable.push(fetched.source);
                }
            }
        }
    }

    // Sort and deduplicate
    hierarchical_list.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.hash.cmp(&b.hash)));
    hierarchical_list.dedup();
    wildcard_patterns.sort();
    wildcard_patterns.dedup();

    let mut engine = FilterEngine {
        fast_map,
        hierarchical_list,
        regex_pool,
        wildcard_patterns,
        keyword_automaton: None,
        keyword_patterns: Vec::new(),
        suspicious_tld_hashes: std::collections::HashSet::new(),
        lexical_strict: true,
        blocked_asn_v4: Vec::new(),
        blocked_asn_v6: Vec::new(),
        geoip_reader: None,
        geoip_file_meta: None,
        suspicious_country_codes: std::collections::HashSet::new(),
        suspicious_country_score: 3,
        custom_flag_maps: Vec::new(),
        seed,
    };

    engine.load_tld_filters(cfg);
    // TLD entries were appended after the initial sort — restore the
    // sort invariant so binary_search_by_key in is_suffix_blocked works.
    engine
        .hierarchical_list
        .sort_by(|a, b| a.depth.cmp(&b.depth).then(a.hash.cmp(&b.hash)));
    engine.load_lexical_filters(cfg);
    engine.load_asn_filters(cfg);
    engine.load_geoip_filter(cfg);

    BuiltEngine {
        engine,
        host_index,
        browser_rules,
        unreadable,
    }
}

/// Reload all filter lists from configured sources (files + URLs).
///
/// Builds a new `FilterEngine` from scratch and atomically replaces the
/// global `CURRENT_ENGINE`. Called at startup, on SIGHUP and by the update
/// task, which uses the returned report to retry early when degraded.
///
/// The whole operation is bounded by `sources.reload_timeout_secs`; set it
/// to `0` to disable the timeout. On timeout the previous engine is kept:
/// the new one is only published once fully built.
pub async fn reload_lists() -> ReloadReport {
    let timeout_secs = CONFIG.load().sources.reload_timeout_secs;
    if timeout_secs == 0 {
        return reload_lists_inner().await;
    }
    match tokio::time::timeout(
        std::time::Duration::from_secs(u64::from(timeout_secs)),
        reload_lists_inner(),
    )
    .await
    {
        Ok(report) => report,
        Err(_) => {
            eprintln!(
                "Error: list reload timed out after {}s — previous engine retained",
                timeout_secs
            );
            ReloadReport {
                timed_out: true,
                ..ReloadReport::default()
            }
        }
    }
}

async fn reload_lists_inner() -> ReloadReport {
    println!("Loading filter lists...");
    let client = build_https_client();
    let cfg = CONFIG.load_full();
    let seed = GLOBAL_SEED.load(Ordering::Relaxed);
    let sources = &cfg.sources;
    let policy = FetchPolicy::from_config(&cfg);
    let cache_dir = sources.list_cache_dir.as_str();
    let mut report = ReloadReport::default();

    // Whitelists first, then NRD, then blacklists: the order entries are
    // merged in, as before.
    let mut plan: Vec<(&str, DomainEntryFlags, bool)> = Vec::new();
    plan.extend(
        sources
            .whitelists
            .iter()
            .map(|s| (s.as_str(), DomainEntryFlags::WHITELIST, false)),
    );
    if !sources.nrd_list_path.is_empty() {
        plan.push((sources.nrd_list_path.as_str(), DomainEntryFlags::NRD, true));
    }
    plan.extend(
        sources
            .blacklists
            .iter()
            .map(|s| (s.as_str(), DomainEntryFlags::NONE, true)),
    );

    let mut fetched = Vec::with_capacity(plan.len());
    for (source, flags, filtered) in plan {
        println!("Loading list from {}", source);
        if let Some(source) = fetch_source(
            source,
            flags,
            filtered,
            &client,
            policy,
            cache_dir,
            &mut report,
        )
        .await
        {
            fetched.push(source);
        }
    }

    let build_cfg = Arc::clone(&cfg);
    let built =
        match tokio::task::spawn_blocking(move || build_engine(fetched, &build_cfg, seed)).await {
            Ok(built) => built,
            Err(e) => {
                eprintln!("Error: list build failed: {} — previous engine retained", e);
                report.timed_out = true;
                return report;
            }
        };
    report.missing.extend(built.unreadable);

    CURRENT_ENGINE.store(Arc::new(built.engine));

    // Phase 4: a fresh filter engine may now block a domain that was
    // previously allowed and therefore cached + tracked. Drop both
    // mirrors so the next client query re-evaluates the policy.
    if let Some(cache) = crate::RESPONSE_CACHE.get() {
        cache.clear();
    }
    crate::POPULARITY_TRACKER.clear();

    let host_index_path = cfg.sources.host_index_path.clone();
    let browser_rules_path = cfg.sources.browser_rules_path.clone();
    let (host_index, browser_rules) = (built.host_index, built.browser_rules);
    let written = tokio::task::spawn_blocking(move || {
        if !host_index_path.is_empty()
            && let Err(e) = host_index::write_host_index(&host_index_path, &host_index)
        {
            eprintln!("Warning: Failed to write host index: {}", e);
        }
        if !browser_rules_path.is_empty()
            && let Err(e) = write_browser_rules(&browser_rules_path, &browser_rules)
        {
            eprintln!("Warning: Failed to write browser rules: {}", e);
        }
    })
    .await;
    if let Err(e) = written {
        eprintln!("Warning: Failed to write list outputs: {}", e);
    }

    report
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::resolve::tests::run_with_globals;

    /// A canned HTTP response: status, extra headers, body, and whether to
    /// send `Content-Length` (without it the body ends at connection close).
    struct Reply {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
        content_length: bool,
    }

    impl Reply {
        fn ok(body: &str) -> Self {
            Self {
                status: 200,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
                content_length: true,
            }
        }

        fn status(status: u16) -> Self {
            Self {
                status,
                ..Self::ok("")
            }
        }

        fn redirect(location: &str) -> Self {
            Self {
                headers: vec![("Location", location.to_owned())],
                ..Self::status(301)
            }
        }
    }

    type Handler = Arc<dyn Fn(&str) -> Reply + Send + Sync>;

    /// Minimal HTTP/1.1 server on 127.0.0.1: one request per connection,
    /// answered by `handler(path)`. Returns the base URL and a request
    /// counter.
    async fn spawn_http(handler: Handler) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, AtomicOrdering::SeqCst);
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&request);
                    let path = text.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    let reply = handler(&path);
                    let mut head = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", reply.status);
                    if reply.content_length {
                        head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
                    }
                    for (name, value) in &reply.headers {
                        head.push_str(&format!("{name}: {value}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&reply.body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (base, hits)
    }

    fn policy(allow_insecure_http: bool, max_bytes: usize) -> FetchPolicy {
        FetchPolicy {
            allow_insecure_http,
            max_bytes,
        }
    }

    async fn download(url: &str, policy: FetchPolicy) -> Result<String, DownloadError> {
        download_list(&build_https_client(), &Url::parse(url).unwrap(), policy).await
    }

    // ---- download_list ----

    #[tokio::test]
    async fn download_refuses_plain_http_by_default() {
        let (base, hits) = spawn_http(Arc::new(|_| Reply::ok("ads.com\n"))).await;
        let err = download(&format!("{base}/list"), policy(false, 1024))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("allow_insecure_http"), "{err}");
        assert_eq!(hits.load(AtomicOrdering::SeqCst), 0, "no connection made");
    }

    #[tokio::test]
    async fn download_follows_redirects() {
        let (base, _) = spawn_http(Arc::new(|path| match path {
            "/old" => Reply::redirect("/moved"),
            "/moved" => Reply::redirect("/list"),
            _ => Reply::ok("ads.com\n"),
        }))
        .await;
        let body = download(&format!("{base}/old"), policy(true, 1024))
            .await
            .unwrap();
        assert_eq!(body, "ads.com\n");
    }

    #[tokio::test]
    async fn download_gives_up_after_too_many_redirects() {
        let (base, hits) = spawn_http(Arc::new(|_| Reply::redirect("/loop"))).await;
        let err = download(&format!("{base}/loop"), policy(true, 1024))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("redirects"), "{err}");
        assert_eq!(hits.load(AtomicOrdering::SeqCst), MAX_REDIRECTS + 1);
    }

    #[tokio::test]
    async fn download_refuses_redirect_to_plain_http() {
        // An HTTPS list must not be downgraded by a redirect; here the
        // policy check fires on the redirect target before any request.
        let checked = policy(false, 1024).check_scheme(&Url::parse("http://lists.test/x").unwrap());
        assert!(checked.is_err());
        assert!(
            policy(false, 1024)
                .check_scheme(&Url::parse("https://lists.test/x").unwrap())
                .is_ok()
        );
        assert!(
            policy(true, 1024)
                .check_scheme(&Url::parse("ftp://lists.test/x").unwrap())
                .is_err()
        );
    }

    #[tokio::test]
    async fn download_refuses_oversized_bodies() {
        let big = "a".repeat(4096);
        let declared = big.clone();
        let (base, _) = spawn_http(Arc::new(move |path| {
            let mut reply = Reply::ok(&declared);
            // `/stream` omits Content-Length: the cap must hold while reading.
            reply.content_length = path != "/stream";
            reply
        }))
        .await;
        for path in ["/declared", "/stream"] {
            let result = download(&format!("{base}{path}"), policy(true, 1024)).await;
            assert!(result.is_err(), "{path} must be refused");
        }
        assert_eq!(
            download(&format!("{base}/declared"), policy(true, 8192))
                .await
                .unwrap(),
            big
        );
    }

    #[tokio::test]
    async fn download_reports_http_errors() {
        let (base, _) = spawn_http(Arc::new(|_| Reply::status(503))).await;
        let err = download(&format!("{base}/list"), policy(true, 1024))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("503"), "{err}");
    }

    // ---- fetch_source: last valid copy ----

    async fn fetch(url: &str, cache_dir: &str, report: &mut ReloadReport) -> Option<String> {
        let fetched = fetch_source(
            url,
            DomainEntryFlags::NONE,
            true,
            &build_https_client(),
            policy(true, 1024),
            cache_dir,
            report,
        )
        .await?;
        match fetched.content {
            SourceContent::Text(text) => Some(text),
            SourceContent::File(_) => panic!("URL source must be text"),
        }
    }

    /// Server answering `/list` with `body` while `healthy`, 500 otherwise.
    async fn flaky_server(body: &'static str) -> (String, Arc<std::sync::atomic::AtomicBool>) {
        let healthy = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let state = Arc::clone(&healthy);
        let (base, _) = spawn_http(Arc::new(move |_| {
            if state.load(AtomicOrdering::SeqCst) {
                Reply::ok(body)
            } else {
                Reply::status(500)
            }
        }))
        .await;
        (format!("{base}/list"), healthy)
    }

    #[tokio::test]
    async fn failed_download_falls_back_to_the_disk_copy() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().to_str().unwrap();
        let (url, healthy) = flaky_server("ads.com\n").await;

        let mut report = ReloadReport::default();
        assert_eq!(
            fetch(&url, cache_dir, &mut report).await.unwrap(),
            "ads.com\n"
        );
        assert!(!report.is_degraded());
        assert!(last_good_path(dir.path(), &url).exists());

        healthy.store(false, AtomicOrdering::SeqCst);
        let mut report = ReloadReport::default();
        assert_eq!(
            fetch(&url, cache_dir, &mut report).await.unwrap(),
            "ads.com\n"
        );
        assert_eq!(report.stale, std::slice::from_ref(&url));
    }

    #[tokio::test]
    async fn failed_download_falls_back_to_memory_without_cache_dir() {
        let (url, healthy) = flaky_server("tracker.net\n").await;
        let mut report = ReloadReport::default();
        fetch(&url, "", &mut report).await.unwrap();
        healthy.store(false, AtomicOrdering::SeqCst);
        let mut report = ReloadReport::default();
        assert_eq!(fetch(&url, "", &mut report).await.unwrap(), "tracker.net\n");
        assert_eq!(report.stale, [url]);
    }

    #[tokio::test]
    async fn failed_download_without_copy_is_reported_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (url, healthy) = flaky_server("ads.com\n").await;
        healthy.store(false, AtomicOrdering::SeqCst);
        let mut report = ReloadReport::default();
        assert!(
            fetch(&url, dir.path().to_str().unwrap(), &mut report)
                .await
                .is_none()
        );
        assert_eq!(report.missing, [url]);
    }

    #[tokio::test]
    async fn refused_download_keeps_the_previous_copy_intact() {
        // An oversized (or insecure) answer is a failed download: the last
        // valid copy is served and not overwritten.
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().to_str().unwrap();
        let big = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let state = Arc::clone(&big);
        let (base, _) = spawn_http(Arc::new(move |_| {
            if state.load(AtomicOrdering::SeqCst) {
                Reply::ok(&"x".repeat(4096))
            } else {
                Reply::ok("ads.com\n")
            }
        }))
        .await;
        let url = format!("{base}/list");
        fetch(&url, cache_dir, &mut ReloadReport::default())
            .await
            .unwrap();
        big.store(true, AtomicOrdering::SeqCst);
        let mut report = ReloadReport::default();
        assert_eq!(
            fetch(&url, cache_dir, &mut report).await.unwrap(),
            "ads.com\n"
        );
        assert_eq!(report.stale, [url]);
    }

    // ---- reload_lists end to end ----

    fn install_sources(blacklists: Vec<String>, cache_dir: &str) {
        let mut config = Config::default();
        config.sources.blacklists = blacklists;
        config.sources.whitelists = Vec::new();
        config.sources.nrd_list_path = String::new();
        config.sources.host_index_path = String::new();
        config.sources.browser_rules_path = String::new();
        config.sources.allow_insecure_http = true;
        config.sources.list_cache_dir = cache_dir.to_owned();
        config.sources.reload_timeout_secs = 30;
        CONFIG.store(Arc::new(config));
    }

    fn is_listed(domain: &str) -> bool {
        let hash =
            twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), domain.as_bytes());
        CURRENT_ENGINE.load().fast_map.contains_key(&hash)
    }

    #[test]
    fn outage_during_update_keeps_the_list() {
        // Review E6: a network failure at update time used to rebuild the
        // engine without the list.
        run_with_globals(async {
            let dir = tempfile::tempdir().unwrap();
            let (url, healthy) = flaky_server("0.0.0.0 ads-outage.com\n").await;
            install_sources(vec![url.clone()], dir.path().to_str().unwrap());

            let report = reload_lists().await;
            assert!(!report.is_degraded(), "{report:?}");
            assert!(is_listed("ads-outage.com"));

            healthy.store(false, AtomicOrdering::SeqCst);
            let report = reload_lists().await;
            assert_eq!(report.stale, [url]);
            assert!(is_listed("ads-outage.com"), "the last valid copy is kept");
        });
    }

    #[test]
    fn cold_start_without_network_uses_the_disk_copy() {
        run_with_globals(async {
            let dir = tempfile::tempdir().unwrap();
            let cache_dir = dir.path().to_str().unwrap();
            let (url, healthy) = flaky_server("0.0.0.0 ads-boot.com\n").await;
            install_sources(vec![url.clone()], cache_dir);
            reload_lists().await;

            // "Restart" with the network down: empty engine, server failing.
            CURRENT_ENGINE.store(Arc::new(FilterEngine::empty()));
            healthy.store(false, AtomicOrdering::SeqCst);
            let report = reload_lists().await;
            assert!(report.is_degraded());
            assert!(is_listed("ads-boot.com"));
        });
    }

    #[test]
    fn reload_build_does_not_block_the_runtime() {
        // Parsing runs on the blocking pool: a timer on the same
        // single-threaded runtime keeps ticking while a large list loads.
        run_with_globals(async {
            let dir = tempfile::tempdir().unwrap();
            let list = dir.path().join("big.txt");
            let content: String = (0..30_000)
                .map(|idx| format!("0.0.0.0 host{idx}.example-big.com\n"))
                .collect();
            std::fs::write(&list, content).unwrap();
            install_sources(vec![list.to_str().unwrap().to_owned()], "");

            let ticks = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&ticks);
            let ticker = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    counter.fetch_add(1, AtomicOrdering::SeqCst);
                }
            });
            let started = std::time::Instant::now();
            let report = reload_lists().await;
            let elapsed = started.elapsed();
            ticker.abort();

            assert!(!report.is_degraded(), "{report:?}");
            assert!(is_listed("host29999.example-big.com"));
            assert!(
                ticks.load(AtomicOrdering::SeqCst) >= 3,
                "runtime starved: {} ticks during a {elapsed:?} reload",
                ticks.load(AtomicOrdering::SeqCst)
            );
        });
    }

    #[test]
    fn unreadable_file_source_is_reported_missing() {
        run_with_globals(async {
            install_sources(vec!["/nonexistent/dgaard-list.txt".to_owned()], "");
            let report = reload_lists().await;
            assert_eq!(report.missing, ["/nonexistent/dgaard-list.txt"]);
        });
    }
}
