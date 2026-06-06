use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use dgaard_engine::{Action, BlockReason, ResolveResult, resolve_with_score};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::AppState;

const MAX_DOMAIN_LEN: usize = 253;

#[derive(Debug, Deserialize)]
struct CheckRequest {
    domain: Option<String>,
}

#[derive(Debug, Serialize)]
struct CheckResponse {
    domain: String,
    score: u8,
    blocked: bool,
    action: String,
    reasons: Vec<String>,
}

fn action_to_fields(action: &Action) -> (bool, String) {
    match action {
        Action::Block(reason) => (true, format!("Block({})", format_reason(reason))),
        Action::Allow => (false, String::from("Allow")),
        Action::ProxyToUpstream => (false, String::from("ProxyToUpstream")),
        Action::LocalResolve(ip) => (false, format!("LocalResolve({ip})")),
        Action::InternalRedirect(ip) => (false, format!("InternalRedirect({ip})")),
        Action::Drop => (false, String::from("Drop")),
        Action::Respond(ip) => (false, format!("Respond({ip})")),
        Action::Redirect(ip) => (false, format!("Redirect({ip})")),
    }
}

pub fn format_reason(reason: &BlockReason) -> String {
    match reason {
        BlockReason::StaticBlacklist(list) => format!("StaticBlacklist({list})"),
        BlockReason::AbpRule(rule) => format!("AbpRule({rule})"),
        BlockReason::HighEntropy(score) => format!("HighEntropy({score:.2})"),
        BlockReason::LexicalAnalysis => String::from("LexicalAnalysis"),
        BlockReason::BannedKeyword(kw) => format!("BannedKeyword({kw})"),
        BlockReason::InvalidStructure => String::from("InvalidStructure"),
        BlockReason::SuspiciousIdn => String::from("SuspiciousIdn"),
        BlockReason::NrdList => String::from("NrdList"),
        BlockReason::Suspicious => String::from("Suspicious"),
        BlockReason::TldExcluded => String::from("TldExcluded"),
        BlockReason::CnameCloaking => String::from("CnameCloaking"),
        BlockReason::ForbiddenQType(qt) => format!("ForbiddenQType({qt})"),
        BlockReason::DnsRebinding => String::from("DnsRebinding"),
        BlockReason::LowTtl(ttl) => format!("LowTtl({ttl})"),
        BlockReason::AsnBlocked => String::from("AsnBlocked"),
    }
}

fn result_to_response(domain: &str, result: ResolveResult) -> CheckResponse {
    let (blocked, action) = action_to_fields(&result.action);
    let reasons = result.score.reasons.iter().map(format_reason).collect();
    CheckResponse {
        domain: domain.to_string(),
        score: result.score.total,
        blocked,
        action,
        reasons,
    }
}

/// POST /api/v1/check — score a domain through the engine.
///
/// Request body:  `{"domain": "example.com"}`
/// Response body: `{"domain": str, "score": u8, "blocked": bool, "action": str, "reasons": [str]}`
///
/// Returns `ApiError::BadRequest` if `domain` is missing or empty (HTTP 400).
/// Returns `ApiError::UnprocessableEntity` if `domain` exceeds 253 characters (HTTP 422).
/// Returns HTTP 200 (or 403 when `blocked_status_code = 403`) for normal results.
async fn check_domain(
    State(state): State<AppState>,
    Json(body): Json<CheckRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let domain = match body.domain.as_deref().map(str::trim) {
        None | Some("") => return Err(ApiError::BadRequest("missing or empty domain")),
        Some(s) => s.to_string(),
    };

    if domain.len() > MAX_DOMAIN_LEN {
        return Err(ApiError::UnprocessableEntity(
            "domain exceeds 253 characters",
        ));
    }

    let engine_guard = state.engine.load();
    let config_guard = state.config.load();
    let result = resolve_with_score(&domain, &engine_guard, &config_guard);
    let response = result_to_response(&domain, result);

    let status = if response.blocked && state.blocked_status_code == 403 {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::OK
    };

    let body = serde_json::to_value(&response)
        .unwrap_or_else(|_| serde_json::json!({"error": "internal serialization error"}));
    Ok((status, Json(body)))
}

pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/check", post(check_domain))
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
    fn block_action_sets_blocked_true_and_action_prefix() {
        let result = make_result(Action::Block(BlockReason::StaticBlacklist("adaway".into())));
        let resp = result_to_response("bad.com", result);
        assert!(resp.blocked);
        assert!(resp.action.starts_with("Block("));
        assert_eq!(resp.domain, "bad.com");
    }

    #[test]
    fn allow_action_sets_blocked_false() {
        let result = make_result(Action::Allow);
        let resp = result_to_response("good.com", result);
        assert!(!resp.blocked);
        assert_eq!(resp.action, "Allow");
    }

    #[test]
    fn proxy_to_upstream_sets_blocked_false() {
        let result = make_result(Action::ProxyToUpstream);
        let resp = result_to_response("example.com", result);
        assert!(!resp.blocked);
        assert_eq!(resp.action, "ProxyToUpstream");
    }

    #[test]
    fn score_and_reasons_are_preserved_in_response() {
        let mut score = SuspicionScore::default();
        score.add(4, BlockReason::HighEntropy(4.5));
        let result = ResolveResult {
            action: Action::ProxyToUpstream,
            score,
        };
        let resp = result_to_response("example.com", result);
        assert_eq!(resp.score, 4);
        assert_eq!(resp.reasons.len(), 1);
        assert_eq!(resp.reasons[0], "HighEntropy(4.50)");
    }

    #[test]
    fn all_block_reasons_format_correctly() {
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
        ];
        for (reason, expected) in cases {
            assert_eq!(format_reason(reason), *expected, "failed for {expected}");
        }
    }
}
