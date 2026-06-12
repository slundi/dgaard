use std::sync::Arc;

use arc_swap::ArcSwap;
use dgaard_engine::{
    Action, BlockReason, Config as EngineConfig, FilterEngine, ResolveResult, resolve_with_score,
};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Maximum domain length per RFC 1035.
const MAX_DOMAIN_LEN: usize = 253;

/// JSON response written back to the Unix socket client.
///
/// Wire format: `{"score": u8, "blocked": bool, "action": str, "reasons": [str]}\n`
#[derive(Debug, Serialize)]
pub struct DomainResponse {
    pub score: u8,
    pub blocked: bool,
    pub action: String,
    pub reasons: Vec<String>,
}

impl From<ResolveResult> for DomainResponse {
    fn from(result: ResolveResult) -> Self {
        let (blocked, action) = action_to_fields(&result.action);
        let reasons = result.score.reasons.iter().map(format_reason).collect();
        DomainResponse {
            score: result.score.total,
            blocked,
            action,
            reasons,
        }
    }
}

fn action_to_fields(action: &Action) -> (bool, String) {
    match action {
        Action::Block(reason) => (true, format!("Block({})", format_reason(reason))),
        Action::Allow => (false, String::from("Allow")),
        Action::ProxyToUpstream => (false, String::from("ProxyToUpstream")),
        Action::LocalResolve(ip) => (false, format!("LocalResolve({})", ip)),
        Action::InternalRedirect(ip) => (false, format!("InternalRedirect({})", ip)),
        Action::Drop => (false, String::from("Drop")),
        Action::Respond(ip) => (false, format!("Respond({})", ip)),
        Action::Redirect(ip) => (false, format!("Redirect({})", ip)),
    }
}

pub fn format_reason(reason: &BlockReason) -> String {
    match reason {
        BlockReason::StaticBlacklist(list) => format!("StaticBlacklist({})", list),
        BlockReason::AbpRule(rule) => format!("AbpRule({})", rule),
        BlockReason::HighEntropy(score) => format!("HighEntropy({:.2})", score),
        BlockReason::LexicalAnalysis => String::from("LexicalAnalysis"),
        BlockReason::BannedKeyword(kw) => format!("BannedKeyword({})", kw),
        BlockReason::InvalidStructure => String::from("InvalidStructure"),
        BlockReason::SuspiciousIdn => String::from("SuspiciousIdn"),
        BlockReason::NrdList => String::from("NrdList"),
        BlockReason::Suspicious => String::from("Suspicious"),
        BlockReason::TldExcluded => String::from("TldExcluded"),
        BlockReason::CnameCloaking => String::from("CnameCloaking"),
        BlockReason::ForbiddenQType(qt) => format!("ForbiddenQType({})", qt),
        BlockReason::DnsRebinding => String::from("DnsRebinding"),
        BlockReason::LowTtl(ttl) => format!("LowTtl({})", ttl),
        BlockReason::AsnBlocked => String::from("AsnBlocked"),
        BlockReason::GeoIpSuspicious(code) => format!("GeoIpSuspicious({})", code),
        BlockReason::SpecialUseDomain => String::from("SpecialUseDomain"),
        BlockReason::PtrLeak => String::from("PtrLeak"),
        BlockReason::ChaosClass => String::from("ChaosClass"),
        BlockReason::CustomFlag(bit) => format!("CustomFlag({})", bit),
    }
}

/// Handle one Unix socket connection: read a domain, score it, write JSON response.
///
/// Input:  newline-terminated UTF-8 domain string (`"example.com\n"`)
/// Output: newline-terminated JSON (`{"score":0,"blocked":false,"action":"ProxyToUpstream","reasons":[]}\n`)
///
/// The engine and config are loaded from the `ArcSwap` at the start of the
/// connection, so SIGHUP reloads are visible to new connections immediately.
///
/// Malformed input (empty or > 253 bytes) returns `{"error":"..."}`.
/// IO errors are logged with `log::warn!` and the connection is dropped.
pub async fn handle_connection(
    stream: UnixStream,
    engine: Arc<ArcSwap<FilterEngine>>,
    config: Arc<ArcSwap<EngineConfig>>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader.take(MAX_DOMAIN_LEN as u64 + 2));
    let mut line = String::new();

    match buf_reader.read_line(&mut line).await {
        Ok(0) => return, // EOF with no data
        Ok(_) => {}
        Err(e) => {
            log::warn!("Connection read error: {e}");
            return;
        }
    }

    let domain = line.trim();

    let response = if domain.is_empty() {
        String::from(r#"{"error":"empty domain"}"#)
    } else if domain.len() > MAX_DOMAIN_LEN {
        String::from(r#"{"error":"domain exceeds 253 bytes"}"#)
    } else {
        // Load current engine and config snapshots for this connection.
        // arc-swap ensures we see a consistent pair even during a reload.
        let engine_guard = engine.load();
        let config_guard = config.load();
        let result = resolve_with_score(domain, &engine_guard, &config_guard);
        match serde_json::to_string(&DomainResponse::from(result)) {
            Ok(json) => json,
            Err(e) => {
                log::warn!("Serialization error: {e}");
                String::from(r#"{"error":"internal serialization error"}"#)
            }
        }
    };

    let mut response_line = response;
    response_line.push('\n');
    if let Err(e) = writer.write_all(response_line.as_bytes()).await {
        log::warn!("Connection write error: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dgaard_engine::SuspicionScore;

    fn make_result(action: Action) -> ResolveResult {
        ResolveResult {
            action,
            score: SuspicionScore::default(),
        }
    }

    #[test]
    fn block_action_sets_blocked_true() {
        let result = make_result(Action::Block(BlockReason::StaticBlacklist("adaway".into())));
        let resp = DomainResponse::from(result);
        assert!(resp.blocked);
        assert!(resp.action.starts_with("Block("));
    }

    #[test]
    fn allow_action_sets_blocked_false() {
        let result = make_result(Action::Allow);
        let resp = DomainResponse::from(result);
        assert!(!resp.blocked);
        assert_eq!(resp.action, "Allow");
    }

    #[test]
    fn proxy_to_upstream_action_sets_blocked_false() {
        let result = make_result(Action::ProxyToUpstream);
        let resp = DomainResponse::from(result);
        assert!(!resp.blocked);
        assert_eq!(resp.action, "ProxyToUpstream");
    }

    #[test]
    fn block_serializes_to_json_with_blocked_true() {
        let result = make_result(Action::Block(BlockReason::StaticBlacklist("test".into())));
        let resp = DomainResponse::from(result);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"blocked\":true"));
        assert!(json.contains("\"action\":\"Block("));
    }

    #[test]
    fn allow_serializes_to_json_with_blocked_false() {
        let result = make_result(Action::Allow);
        let resp = DomainResponse::from(result);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"blocked\":false"));
        assert!(json.contains("\"action\":\"Allow\""));
    }

    #[test]
    fn proxy_serializes_to_json_correctly() {
        let result = make_result(Action::ProxyToUpstream);
        let resp = DomainResponse::from(result);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"blocked\":false"));
        assert!(json.contains("\"action\":\"ProxyToUpstream\""));
    }

    #[test]
    fn score_and_reasons_are_preserved() {
        let mut score = SuspicionScore::default();
        score.add(4, BlockReason::HighEntropy(4.5));
        let result = ResolveResult {
            action: Action::ProxyToUpstream,
            score,
        };
        let resp = DomainResponse::from(result);
        assert_eq!(resp.score, 4);
        assert_eq!(resp.reasons.len(), 1);
        assert_eq!(resp.reasons[0], "HighEntropy(4.50)");
    }

    #[test]
    fn all_block_reason_variants_format_correctly() {
        let cases: &[(BlockReason, &str)] = &[
            (
                BlockReason::StaticBlacklist("adaway".into()),
                "StaticBlacklist(adaway)",
            ),
            (BlockReason::AbpRule("wildcard".into()), "AbpRule(wildcard)"),
            (BlockReason::HighEntropy(4.5), "HighEntropy(4.50)"),
            (BlockReason::LexicalAnalysis, "LexicalAnalysis"),
            (
                BlockReason::BannedKeyword("casino".into()),
                "BannedKeyword(casino)",
            ),
            (BlockReason::InvalidStructure, "InvalidStructure"),
            (BlockReason::SuspiciousIdn, "SuspiciousIdn"),
            (BlockReason::NrdList, "NrdList"),
            (BlockReason::Suspicious, "Suspicious"),
            (BlockReason::TldExcluded, "TldExcluded"),
            (BlockReason::CnameCloaking, "CnameCloaking"),
            (BlockReason::ForbiddenQType(255), "ForbiddenQType(255)"),
            (BlockReason::DnsRebinding, "DnsRebinding"),
            (BlockReason::LowTtl(5), "LowTtl(5)"),
            (BlockReason::AsnBlocked, "AsnBlocked"),
            (
                BlockReason::GeoIpSuspicious("RU".into()),
                "GeoIpSuspicious(RU)",
            ),
        ];
        for (reason, expected) in cases {
            assert_eq!(format_reason(reason), *expected, "failed for {:?}", reason);
        }
    }
}
