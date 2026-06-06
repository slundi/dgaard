use dgaard_engine::{Action, BlockReason, ResolveResult};
use serde::Serialize;

/// JSON response written back to the Unix socket client.
///
/// Wire format: `{"score": u8, "blocked": bool, "action": str, "reasons": [str]}\n`
#[derive(Debug, Serialize)]
#[allow(dead_code)] // constructed by Phase D2 connection handler
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

#[allow(dead_code)] // called by Phase D2 connection handler
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
        ];
        for (reason, expected) in cases {
            assert_eq!(format_reason(reason), *expected, "failed for {:?}", reason);
        }
    }
}
