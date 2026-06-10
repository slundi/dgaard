use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::web::state::WebState;

#[derive(Deserialize)]
pub struct ListsParams {
    pub search: Option<String>,
    /// Filter by entry type: `blocked`, `tld`, `wildcard`, or `whitelist`.
    #[serde(rename = "type")]
    pub list_type: Option<String>,
}

#[derive(Serialize)]
pub struct ListEntry {
    pub hash: String,
    pub domain: String,
    #[serde(rename = "type")]
    pub entry_type: &'static str,
    /// All-time query hit count for this domain (from the rolling stats counter).
    pub hits: u64,
}

/// Infer the entry type from the domain string.
///
/// Priority:
///   1. Starts with `*.`            → `"wildcard"`
///   2. Starts with `!`             → `"whitelist"`
///   3. Contains no `.`             → `"tld"`
///   4. Anything else               → `"blocked"`
fn classify(domain: &str) -> &'static str {
    if domain.starts_with("*.") {
        "wildcard"
    } else if domain.starts_with('!') {
        "whitelist"
    } else if !domain.contains('.') {
        "tld"
    } else {
        "blocked"
    }
}

pub async fn lists_handler(
    State(web): State<Arc<WebState>>,
    Query(params): Query<ListsParams>,
) -> Json<Vec<ListEntry>> {
    let domain_map = web.app.domain_map.read().await;
    let stats = web.app.stats.read().await;

    let search = params.search.as_deref().map(str::to_lowercase);

    let mut entries: Vec<ListEntry> = domain_map
        .iter()
        .filter_map(|(hash, domain)| {
            let entry_type = classify(domain);

            if let Some(ref t) = params.list_type {
                if entry_type != t.as_str() {
                    return None;
                }
            }

            if let Some(ref q) = search {
                if !domain.to_lowercase().contains(q.as_str()) {
                    return None;
                }
            }

            let hits = stats.domain_hits.get(hash).copied().unwrap_or(0);

            Some(ListEntry {
                hash: format!("{:016x}", hash),
                domain: domain.clone(),
                entry_type,
                hits,
            })
        })
        .collect();

    drop(stats);
    drop(domain_map);

    // Default sort: type ascending, then domain ascending.
    entries.sort_unstable_by(|a, b| {
        a.entry_type
            .cmp(b.entry_type)
            .then_with(|| a.domain.cmp(&b.domain))
    });

    Json(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use crate::web::state::WebState;
    use axum::extract::State;
    use std::time::Duration;

    async fn make_web_state() -> Arc<WebState> {
        let app = Arc::new(AppState::new(Duration::from_secs(3600)));
        app.insert_domain(1, "example.com".to_string()).await;
        app.insert_domain(2, "*.evil.com".to_string()).await;
        app.insert_domain(3, "com".to_string()).await;
        app.insert_domain(4, "!safe.example.com".to_string()).await;
        Arc::new(WebState::new(app, 100))
    }

    #[test]
    fn classify_blocked() {
        assert_eq!(classify("example.com"), "blocked");
        assert_eq!(classify("sub.example.com"), "blocked");
    }

    #[test]
    fn classify_wildcard() {
        assert_eq!(classify("*.example.com"), "wildcard");
        assert_eq!(classify("*.com"), "wildcard");
    }

    #[test]
    fn classify_tld() {
        assert_eq!(classify("com"), "tld");
        assert_eq!(classify("net"), "tld");
        assert_eq!(classify("xyz"), "tld");
    }

    #[test]
    fn classify_whitelist() {
        assert_eq!(classify("!example.com"), "whitelist");
        assert_eq!(classify("!com"), "whitelist");
    }

    #[tokio::test]
    async fn returns_all_entries() {
        let web = make_web_state().await;
        let Json(entries) =
            lists_handler(State(web), Query(ListsParams { search: None, list_type: None }))
                .await;
        assert_eq!(entries.len(), 4);
    }

    #[tokio::test]
    async fn filter_by_type_blocked() {
        let web = make_web_state().await;
        let Json(entries) = lists_handler(
            State(web),
            Query(ListsParams {
                search: None,
                list_type: Some("blocked".to_string()),
            }),
        )
        .await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "example.com");
    }

    #[tokio::test]
    async fn filter_by_type_wildcard() {
        let web = make_web_state().await;
        let Json(entries) = lists_handler(
            State(web),
            Query(ListsParams {
                search: None,
                list_type: Some("wildcard".to_string()),
            }),
        )
        .await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "*.evil.com");
    }

    #[tokio::test]
    async fn filter_by_search() {
        let web = make_web_state().await;
        let Json(entries) = lists_handler(
            State(web),
            Query(ListsParams {
                search: Some("evil".to_string()),
                list_type: None,
            }),
        )
        .await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "*.evil.com");
    }

    #[tokio::test]
    async fn search_is_case_insensitive() {
        let web = make_web_state().await;
        let Json(entries) = lists_handler(
            State(web),
            Query(ListsParams {
                search: Some("EXAMPLE".to_string()),
                list_type: None,
            }),
        )
        .await;
        // example.com and !safe.example.com both contain "example"
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn default_sort_is_type_then_domain() {
        let web = make_web_state().await;
        let Json(entries) =
            lists_handler(State(web), Query(ListsParams { search: None, list_type: None }))
                .await;
        // Alphabetical type order: blocked < tld < whitelist < wildcard
        let types: Vec<&str> = entries.iter().map(|e| e.entry_type).collect();
        let mut sorted = types.clone();
        sorted.sort();
        assert_eq!(types, sorted);
    }

    #[tokio::test]
    async fn empty_domain_map_returns_empty() {
        let app = Arc::new(AppState::new(Duration::from_secs(3600)));
        let web = Arc::new(WebState::new(app, 100));
        let Json(entries) =
            lists_handler(State(web), Query(ListsParams { search: None, list_type: None }))
                .await;
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn entry_includes_hash_and_hits() {
        let web = make_web_state().await;
        let Json(entries) = lists_handler(
            State(web),
            Query(ListsParams {
                search: Some("example.com".to_string()),
                list_type: Some("blocked".to_string()),
            }),
        )
        .await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hash.len(), 16); // 16 hex chars for u64
        assert_eq!(entries[0].hits, 0); // no events recorded
    }
}
