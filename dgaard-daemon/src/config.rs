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

fn default_nats_url() -> String {
    String::from("nats://127.0.0.1:4222")
}

fn default_nats_subject() -> String {
    String::from("dgaard.scores")
}

/// Optional NATS publisher configuration. Disabled by default.
///
/// When `enabled`, every scoring decision the daemon serves is also
/// published on `subject` as a JSON document so remote dgaard-monitor
/// instances (or any NATS subscriber) can collect a feed of decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsConfig {
    pub enabled: bool,
    pub url: String,
    pub subject: String,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_nats_url(),
            subject: default_nats_subject(),
        }
    }
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

    /// Optional NATS publisher for scoring decisions.
    pub nats: NatsConfig,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            config_file: default_config_file(),
            log_level: default_log_level(),
            nats: NatsConfig::default(),
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
        if let Some(v) = root.get("nats") {
            match v.as_ref() {
                ValueInner::Table(t) => cfg.nats = parse_nats(t)?,
                _ => return Err("nats: expected table".to_string()),
            }
        }

        const KNOWN: &[&str] = &["socket_path", "config_file", "log_level", "nats"];
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

fn parse_nats(table: &toml_span::value::Table<'_>) -> Result<NatsConfig, String> {
    let mut cfg = NatsConfig::default();
    if let Some(v) = table.get("enabled") {
        match v.as_ref() {
            ValueInner::Boolean(b) => cfg.enabled = *b,
            _ => return Err("nats.enabled: expected boolean".to_string()),
        }
    }
    if let Some(v) = table.get("url") {
        match v.as_ref() {
            ValueInner::String(s) => cfg.url = s.to_string(),
            _ => return Err("nats.url: expected string".to_string()),
        }
    }
    if let Some(v) = table.get("subject") {
        match v.as_ref() {
            ValueInner::String(s) => cfg.subject = s.to_string(),
            _ => return Err("nats.subject: expected string".to_string()),
        }
    }
    const KNOWN: &[&str] = &["enabled", "url", "subject"];
    for (key, _) in table.iter() {
        if !KNOWN.contains(&key.name.as_ref()) {
            eprintln!(
                "dgaard-daemon: unrecognised nats config key '{}' (known: {})",
                key.name,
                KNOWN.join(", ")
            );
        }
    }
    Ok(cfg)
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

    #[test]
    fn nats_defaults_to_disabled() {
        let cfg = DaemonConfig::default();
        assert!(!cfg.nats.enabled);
        assert_eq!(cfg.nats.url, "nats://127.0.0.1:4222");
        assert_eq!(cfg.nats.subject, "dgaard.scores");
    }

    #[test]
    fn missing_nats_table_keeps_defaults() {
        let cfg = DaemonConfig::load(r#"socket_path = "/tmp/x.sock""#).unwrap();
        assert!(!cfg.nats.enabled);
    }

    #[test]
    fn nats_section_overrides_fields() {
        let toml = r#"
[nats]
enabled = true
url = "nats://broker.internal:4222"
subject = "site42.scores"
"#;
        let cfg = DaemonConfig::load(toml).unwrap();
        assert!(cfg.nats.enabled);
        assert_eq!(cfg.nats.url, "nats://broker.internal:4222");
        assert_eq!(cfg.nats.subject, "site42.scores");
    }

    #[test]
    fn nats_invalid_field_type_returns_error() {
        let toml = r#"
[nats]
enabled = "yes"
"#;
        assert!(DaemonConfig::load(toml).is_err());
    }
}
