pub use dgaard_engine::filter::engine;
pub use dgaard_engine::filter::engine::FilterEngine;
pub use dgaard_engine::filter::host_index;
pub use dgaard_engine::filter::{load_list_file, write_browser_rules};

use dgaard_engine::filter::load_list_content;
use dgaard_engine::model::{DomainEntry, DomainEntryFlags};

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use regex::Regex;
use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
};
use url::Url;

use crate::updater::{Resource, validate_input};
use crate::{CONFIG, CURRENT_ENGINE, GLOBAL_SEED};

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Empty<Bytes>,
>;

pub(crate) fn build_https_client() -> HttpsClient {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

async fn download_list(
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

/// Load a source (file path or URL) into the filter collections.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn load_source(
    source: &str,
    base_flags: DomainEntryFlags,
    seed: u64,
    client: &HttpsClient,
    fast_map: &mut HashMap<u64, u8>,
    hierarchical_list: &mut Vec<DomainEntry>,
    wildcard_patterns: &mut Vec<String>,
    regex_pool: &mut Vec<Regex>,
    host_index: &mut HashMap<u64, String>,
    browser_rules: &mut Vec<String>,
) {
    match validate_input(source) {
        Ok(Resource::HttpUrl(url)) => match download_list(client, &url).await {
            Ok(content) => {
                println!("Downloaded {} ({} bytes)", source, content.len());
                load_list_content(
                    &content,
                    base_flags,
                    seed,
                    fast_map,
                    hierarchical_list,
                    wildcard_patterns,
                    regex_pool,
                    host_index,
                    browser_rules,
                );
            }
            Err(e) => eprintln!("Warning: Failed to download {}: {}", source, e),
        },
        Ok(Resource::FilePath(_)) => {
            if let Err(e) = load_list_file(
                source,
                base_flags,
                seed,
                fast_map,
                hierarchical_list,
                wildcard_patterns,
                regex_pool,
                host_index,
                browser_rules,
            ) {
                eprintln!("Warning: Failed to load {}: {}", source, e);
            }
        }
        Err(e) => eprintln!("Warning: Invalid source {}: {}", source, e),
    }
}

/// Reload all filter lists from configured sources (files + URLs).
///
/// Builds a new `FilterEngine` from scratch and atomically replaces the
/// global `CURRENT_ENGINE`. Called at startup and on SIGHUP.
pub async fn reload_lists() {
    println!("Loading filter lists...");
    let client = build_https_client();
    let cfg = CONFIG.load();
    let seed = GLOBAL_SEED.load(Ordering::Relaxed);
    let sources = &cfg.sources;

    let mut fast_map: HashMap<u64, u8> = HashMap::new();
    let mut hierarchical_list: Vec<DomainEntry> = Vec::new();
    let mut regex_pool: Vec<Regex> = Vec::new();
    let mut wildcard_patterns: Vec<String> = Vec::new();
    let mut host_index: HashMap<u64, String> = HashMap::new();
    let mut browser_rules: Vec<String> = Vec::new();

    for source in &sources.whitelists {
        println!("Loading whitelist from {}", source);
        load_source(
            source,
            DomainEntryFlags::WHITELIST,
            seed,
            &client,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
            &mut host_index,
            &mut browser_rules,
        )
        .await;
    }

    if !sources.nrd_list_path.is_empty() {
        println!("Loading NRD list from {}", sources.nrd_list_path);
        load_source(
            &sources.nrd_list_path,
            DomainEntryFlags::NRD,
            seed,
            &client,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
            &mut host_index,
            &mut browser_rules,
        )
        .await;
    }

    for source in &sources.blacklists {
        println!("Loading blacklist from {}", source);
        load_source(
            source,
            DomainEntryFlags::NONE,
            seed,
            &client,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
            &mut host_index,
            &mut browser_rules,
        )
        .await;
    }

    // Sort and deduplicate
    hierarchical_list.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.hash.cmp(&b.hash)));
    hierarchical_list.dedup();
    wildcard_patterns.sort();
    wildcard_patterns.dedup();

    let mut new_engine = FilterEngine {
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
        suspicious_country_codes: std::collections::HashSet::new(),
        suspicious_country_score: 3,
        seed,
    };

    new_engine.load_tld_filters(&cfg);
    new_engine.load_lexical_filters(&cfg);
    new_engine.load_asn_filters(&cfg);
    new_engine.load_geoip_filter(&cfg);

    CURRENT_ENGINE.store(Arc::new(new_engine));

    if !cfg.sources.host_index_path.is_empty()
        && let Err(e) = host_index::write_host_index(&cfg.sources.host_index_path, &host_index)
    {
        eprintln!("Warning: Failed to write host index: {}", e);
    }

    if !cfg.sources.browser_rules_path.is_empty()
        && let Err(e) = write_browser_rules(&cfg.sources.browser_rules_path, &browser_rules)
    {
        eprintln!("Warning: Failed to write browser rules: {}", e);
    }
}
