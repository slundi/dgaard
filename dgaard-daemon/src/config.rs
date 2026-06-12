use toml_span::value::ValueInner;

fn default_socket_path() -> String {
    String::from("/run/dgaard-daemon.sock")
}

fn default_config_file() -> String {
    String::from("/etc/dgaard/dgaard.toml")
}

fn default_log_level() -> String {
    String::from("info")
}

/// Runtime configuration for dgaard-daemon.
///
/// Maps to `dgaard-daemon.toml`. All fields have sensible defaults so the
/// daemon can start without a configuration file.
#[derive(Debug)]
#[allow(dead_code)] // fields consumed by Phase D2 socket listener
pub struct DaemonConfig {
    /// Path to the Unix domain socket the daemon will listen on.
    pub socket_path: String,

    /// Path to the dgaard-engine configuration file (`dgaard.toml`).
    pub config_file: String,

    /// `env_logger`-compatible log level filter (e.g. `"info"`, `"debug"`).
    pub log_level: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            config_file: default_config_file(),
            log_level: default_log_level(),
        }
    }
}

impl DaemonConfig {
    pub fn load(content: &str) -> Result<Self, String> {
        let value = toml_span::parse(content).map_err(|e| e.to_string())?;

        let root = match value.as_ref() {
            ValueInner::Table(t) => t,
            _ => return Err("expected a TOML table at root".to_string()),
        };

        let mut cfg = DaemonConfig::default();

        if let Some(v) = root.get("socket_path") {
            match v.as_ref() {
                ValueInner::String(s) => cfg.socket_path = s.to_string(),
                _ => return Err("socket_path: expected string".to_string()),
            }
        }
        if let Some(v) = root.get("config_file") {
            match v.as_ref() {
                ValueInner::String(s) => cfg.config_file = s.to_string(),
                _ => return Err("config_file: expected string".to_string()),
            }
        }
        if let Some(v) = root.get("log_level") {
            match v.as_ref() {
                ValueInner::String(s) => cfg.log_level = s.to_string(),
                _ => return Err("log_level: expected string".to_string()),
            }
        }

        const KNOWN: &[&str] = &["socket_path", "config_file", "log_level"];
        for (key, _) in root.iter() {
            if !KNOWN.contains(&key.name.as_ref()) {
                eprintln!(
                    "dgaard-daemon: unrecognised config key '{}' (known: {})",
                    key.name,
                    KNOWN.join(", ")
                );
            }
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_socket_path_is_run() {
        assert_eq!(
            DaemonConfig::default().socket_path,
            "/run/dgaard-daemon.sock"
        );
    }

    #[test]
    fn default_config_file_is_etc_dgaard() {
        assert_eq!(
            DaemonConfig::default().config_file,
            "/etc/dgaard/dgaard.toml"
        );
    }

    #[test]
    fn default_log_level_is_info() {
        assert_eq!(DaemonConfig::default().log_level, "info");
    }

    #[test]
    fn load_partial_toml_applies_defaults_for_missing_fields() {
        let toml = r#"socket_path = "/tmp/test.sock""#;
        let cfg = DaemonConfig::load(toml).unwrap();
        assert_eq!(cfg.socket_path, "/tmp/test.sock");
        assert_eq!(cfg.config_file, "/etc/dgaard/dgaard.toml");
        assert_eq!(cfg.log_level, "info");
    }

    #[test]
    fn load_full_toml_overrides_all_fields() {
        let toml = r#"
socket_path = "/var/run/custom.sock"
config_file = "/etc/custom/engine.toml"
log_level = "debug"
"#;
        let cfg = DaemonConfig::load(toml).unwrap();
        assert_eq!(cfg.socket_path, "/var/run/custom.sock");
        assert_eq!(cfg.config_file, "/etc/custom/engine.toml");
        assert_eq!(cfg.log_level, "debug");
    }

    #[test]
    fn load_invalid_toml_returns_error() {
        assert!(DaemonConfig::load("not = [valid toml").is_err());
    }

    #[test]
    fn load_toml_with_unknown_key_still_succeeds() {
        // A misspelled key must not cause an error — the daemon should start
        // with defaults and warn the operator (via eprintln).
        let toml = r#"
socket_path = "/tmp/test.sock"
typo_socket_path = "/typo/ignored.sock"
"#;
        let cfg = DaemonConfig::load(toml).unwrap();
        // The valid key is applied; the typo is silently warned and discarded.
        assert_eq!(cfg.socket_path, "/tmp/test.sock");
    }
}
