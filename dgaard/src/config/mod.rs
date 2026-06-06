pub use dgaard_engine::config::*;

use std::path::{Path, PathBuf};

const SYSTEM_PATH: &str = "/etc/dgaard/config.toml";
const LOCAL_PATH: &str = "dgaard.toml";

/// Resolve the configuration file path using the following priority:
///
/// 1. Explicit `--config <FILE>` CLI override.
/// 2. System path: `/etc/dgaard/config.toml`.
/// 3. Local path: `./dgaard.toml` (relative to CWD).
///
/// Returns `None` if no file is found at any location.
pub fn discover_path(override_path: Option<&str>) -> Option<PathBuf> {
    discover_from_candidates(override_path, &[SYSTEM_PATH, LOCAL_PATH])
}

fn discover_from_candidates(override_path: Option<&str>, candidates: &[&str]) -> Option<PathBuf> {
    if let Some(path) = override_path {
        return Some(PathBuf::from(path));
    }
    for candidate in candidates {
        let path = Path::new(candidate);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    fn create_temp_dir() -> PathBuf {
        let dir = env::temp_dir().join(format!("dgaard_test_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn explicit_override_is_returned_unconditionally() {
        let result = discover_from_candidates(Some("/custom/dgaard.toml"), &[]);
        assert_eq!(result, Some(PathBuf::from("/custom/dgaard.toml")));
    }

    #[test]
    fn explicit_override_does_not_check_existence() {
        let result = discover_from_candidates(Some("/nonexistent/path.toml"), &[]);
        assert_eq!(result, Some(PathBuf::from("/nonexistent/path.toml")));
    }

    #[test]
    fn no_candidates_returns_none() {
        let result = discover_from_candidates(None, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn absent_candidates_return_none() {
        let result = discover_from_candidates(None, &["/no/such/file.toml", "/also/missing.toml"]);
        assert!(result.is_none());
    }

    #[test]
    fn first_existing_candidate_is_returned() {
        let dir = create_temp_dir();
        let first = dir.join("system.toml");
        let second = dir.join("local.toml");

        fs::write(&first, "").unwrap();
        fs::write(&second, "").unwrap();

        let result =
            discover_from_candidates(None, &[first.to_str().unwrap(), second.to_str().unwrap()]);
        assert_eq!(result, Some(first));
        cleanup(&dir);
    }

    #[test]
    fn second_candidate_used_when_first_absent() {
        let dir = create_temp_dir();
        let missing = dir.join("missing.toml");
        let present = dir.join("local.toml");

        fs::write(&present, "").unwrap();

        let result = discover_from_candidates(
            None,
            &[missing.to_str().unwrap(), present.to_str().unwrap()],
        );
        assert_eq!(result, Some(present));
        cleanup(&dir);
    }

    #[test]
    fn override_wins_over_existing_candidate() {
        let dir = create_temp_dir();
        let candidate = dir.join("candidate.toml");
        fs::write(&candidate, "").unwrap();

        let result = discover_from_candidates(
            Some("/explicit/override.toml"),
            &[candidate.to_str().unwrap()],
        );
        assert_eq!(result, Some(PathBuf::from("/explicit/override.toml")));
        cleanup(&dir);
    }

    #[test]
    fn public_api_smoke_test() {
        let _result: Option<PathBuf> = discover_path(None);
        let explicit = discover_path(Some("/tmp/smoke.toml"));
        assert_eq!(explicit, Some(PathBuf::from("/tmp/smoke.toml")));
    }
}
