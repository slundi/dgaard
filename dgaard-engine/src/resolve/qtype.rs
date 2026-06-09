//! QType and QClass Warden — policy-based DNS query filtering.

use crate::config::Config;
use crate::model::BlockReason;

/// DNS CHAOS class numeric value (RFC 1035 §3.2.4).
const QCLASS_CHAOS: u16 = 3;

/// Check whether the given DNS record type should be blocked by policy.
///
/// Returns `Some(BlockReason::ForbiddenQType(qtype))` if the type is in the
/// configured `security.qtype_warden.blocked_types` list, `None` otherwise.
pub fn check_qtype(qtype: u16, config: &Config) -> Option<BlockReason> {
    let warden = &config.security.qtype_warden;

    if !warden.enabled {
        return None;
    }

    if warden.blocked_types.contains(&qtype) {
        return Some(BlockReason::ForbiddenQType(qtype));
    }

    None
}

/// Check whether the given DNS query class should be blocked by policy.
///
/// Returns `Some(BlockReason::ChaosClass)` if `qclass` is CHAOS (3) and
/// `security.structure.block_chaos_class` is `true`, `None` otherwise.
pub fn check_qclass(qclass: u16, config: &Config) -> Option<BlockReason> {
    if config.security.structure.block_chaos_class && qclass == QCLASS_CHAOS {
        return Some(BlockReason::ChaosClass);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_check_qtype_null_blocked_by_default() {
        let config = Config::default();
        let result = check_qtype(10, &config);
        assert!(matches!(result, Some(BlockReason::ForbiddenQType(10))));
    }

    #[test]
    fn test_check_qtype_a_allowed() {
        let config = Config::default();
        assert!(check_qtype(1, &config).is_none());
    }

    #[test]
    fn test_check_qtype_disabled() {
        let mut config = Config::default();
        config.security.qtype_warden.enabled = false;
        assert!(check_qtype(10, &config).is_none());
        assert!(check_qtype(255, &config).is_none());
    }

    #[test]
    fn test_check_qtype_custom_list() {
        let mut config = Config::default();
        config.security.qtype_warden.enabled = true;
        config.security.qtype_warden.blocked_types = vec![252];
        assert!(check_qtype(252, &config).is_some());
        assert!(check_qtype(10, &config).is_none());
    }

    #[test]
    fn test_check_qtype_carries_type_code() {
        let mut config = Config::default();
        config.security.qtype_warden.enabled = true;
        config.security.qtype_warden.blocked_types = vec![13];
        match check_qtype(13, &config) {
            Some(BlockReason::ForbiddenQType(code)) => assert_eq!(code, 13),
            other => panic!("Expected ForbiddenQType(13), got {:?}", other),
        }
    }

    // --- check_qclass ---

    #[test]
    fn test_check_qclass_chaos_blocked_by_default() {
        let config = Config::default();
        assert!(matches!(
            check_qclass(3, &config),
            Some(BlockReason::ChaosClass)
        ));
    }

    #[test]
    fn test_check_qclass_in_allowed() {
        let config = Config::default();
        assert!(check_qclass(1, &config).is_none());
    }

    #[test]
    fn test_check_qclass_chaos_disabled() {
        let mut config = Config::default();
        config.security.structure.block_chaos_class = false;
        assert!(check_qclass(3, &config).is_none());
    }

    #[test]
    fn test_check_qclass_unknown_class_allowed() {
        let config = Config::default();
        // class 4 (HS/Hesiod) is not CHAOS — should not be blocked
        assert!(check_qclass(4, &config).is_none());
        // class 255 (ANY) is not CHAOS
        assert!(check_qclass(255, &config).is_none());
    }
}
