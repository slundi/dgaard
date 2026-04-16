//! QType Warden — policy-based DNS query-type filtering.
//!
//! Blocks queries whose record type is in the configured `blocked_types` list
//! before any domain-level processing occurs. This check runs at the packet
//! layer and is the cheapest possible filter (a u16 membership test).
//!
//! ## Default blocked types
//! | Code | Name  | Threat vector                             |
//! |------|-------|-------------------------------------------|
//! |  10  | NULL  | DNS tunneling (iodine, dnscat2, heyoka)   |
//! |  13  | HINFO | Host-info leakage                         |
//! | 255  | ANY   | DNS amplification / zone enumeration      |

use crate::CONFIG;
use crate::model::BlockReason;

/// Check whether the given DNS record type should be blocked by policy.
///
/// Returns `Some(BlockReason::ForbiddenQType(qtype))` if the type is in the
/// configured `security.qtype_warden.blocked_types` list, `None` otherwise.
///
/// This function is called once per incoming packet, before the domain is
/// passed to the filter pipeline, so it must remain allocation-free.
///
/// # Arguments
/// * `qtype` — Raw RFC 1035 query-type code from the DNS question section.
pub fn check_qtype(qtype: u16) -> Option<BlockReason> {
    let config = CONFIG.load();
    let warden = &config.security.qtype_warden;

    if !warden.enabled {
        return None;
    }

    if warden.blocked_types.contains(&qtype) {
        return Some(BlockReason::ForbiddenQType(qtype));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::sync::Arc;

    fn setup_default_config() {
        crate::GLOBAL_SEED.store(42, std::sync::atomic::Ordering::Relaxed);
        crate::CONFIG.store(Arc::new(Config::default()));
    }

    fn setup_config_with_types(enabled: bool, blocked: &[u16]) {
        crate::GLOBAL_SEED.store(42, std::sync::atomic::Ordering::Relaxed);
        let mut config = Config::default();
        config.security.qtype_warden.enabled = enabled;
        config.security.qtype_warden.blocked_types = blocked.to_vec();
        crate::CONFIG.store(Arc::new(config));
    }

    #[test]
    fn test_check_qtype_null_blocked_by_default() {
        setup_default_config();
        // NULL = 10, blocked in default config
        let result = check_qtype(10);
        assert!(result.is_some());
        assert!(matches!(result, Some(BlockReason::ForbiddenQType(10))));
    }

    #[test]
    fn test_check_qtype_hinfo_blocked_by_default() {
        setup_default_config();
        // HINFO = 13
        let result = check_qtype(13);
        assert!(matches!(result, Some(BlockReason::ForbiddenQType(13))));
    }

    #[test]
    fn test_check_qtype_any_blocked_by_default() {
        setup_default_config();
        // ANY = 255
        let result = check_qtype(255);
        assert!(matches!(result, Some(BlockReason::ForbiddenQType(255))));
    }

    #[test]
    fn test_check_qtype_a_allowed() {
        setup_default_config();
        // A = 1 — normal query, never blocked
        assert!(check_qtype(1).is_none());
    }

    #[test]
    fn test_check_qtype_aaaa_allowed() {
        setup_default_config();
        // AAAA = 28
        assert!(check_qtype(28).is_none());
    }

    #[test]
    fn test_check_qtype_txt_allowed() {
        setup_default_config();
        // TXT = 16
        assert!(check_qtype(16).is_none());
    }

    #[test]
    fn test_check_qtype_disabled() {
        setup_config_with_types(false, &[10, 13, 255]);
        // Warden disabled — all types pass
        assert!(check_qtype(10).is_none());
        assert!(check_qtype(255).is_none());
    }

    #[test]
    fn test_check_qtype_empty_list() {
        setup_config_with_types(true, &[]);
        // Enabled but no types listed — everything passes
        assert!(check_qtype(10).is_none());
        assert!(check_qtype(255).is_none());
    }

    #[test]
    fn test_check_qtype_custom_list() {
        // Only block AXFR (252) in this config
        setup_config_with_types(true, &[252]);
        assert!(check_qtype(252).is_some());
        assert!(check_qtype(10).is_none()); // NULL not in custom list
        assert!(check_qtype(255).is_none()); // ANY not in custom list
    }

    #[test]
    fn test_check_qtype_carries_type_code() {
        setup_config_with_types(true, &[13]);
        // The returned reason carries the exact type code
        match check_qtype(13) {
            Some(BlockReason::ForbiddenQType(code)) => assert_eq!(code, 13),
            other => panic!("Expected ForbiddenQType(13), got {:?}", other),
        }
    }
}
