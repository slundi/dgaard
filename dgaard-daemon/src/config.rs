use serde::Deserialize;

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
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields consumed by Phase D2 socket listener
pub struct DaemonConfig {
    /// Path to the Unix domain socket the daemon will listen on.
    #[serde(default = "default_socket_path")]
    pub socket_path: String,

    /// Path to the dgaard-engine configuration file (`dgaard.toml`).
    #[serde(default = "default_config_file")]
    pub config_file: String,

    /// `env_logger`-compatible log level filter (e.g. `"info"`, `"debug"`).
    #[serde(default = "default_log_level")]
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
    pub fn load(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
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
}
