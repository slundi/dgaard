//! QType Warden — policy-based DNS query-type filtering.

use crate::config::Config;
use crate::model::BlockReason;

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
}
