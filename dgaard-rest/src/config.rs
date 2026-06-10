use toml_span::value::ValueInner;

fn default_listen_addr() -> String {
    String::from("127.0.0.1:8080")
}

fn default_config_file() -> String {
    String::from("/etc/dgaard/dgaard.toml")
}

fn default_log_level() -> String {
    String::from("info")
}

fn default_blocked_status_code() -> u16 {
    200
}

/// Runtime configuration for dgaard-rest.
///
/// Maps to `dgaard-rest.toml`. All fields have sensible defaults so the
/// server can start without a configuration file.
#[derive(Debug)]
pub struct RestConfig {
    /// Address and port the HTTP server binds to.
    pub listen_addr: String,

    /// Path to the dgaard-engine configuration file (`dgaard.toml`).
    pub config_file: String,

    /// `env_logger`-compatible log level filter (e.g. `"info"`, `"debug"`).
    pub log_level: String,

    /// HTTP status code returned for blocked domains: `200` or `403`.
    pub blocked_status_code: u16,
}

impl Default for RestConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            config_file: default_config_file(),
            log_level: default_log_level(),
            blocked_status_code: default_blocked_status_code(),
        }
    }
}

impl RestConfig {
    pub fn load(content: &str) -> Result<Self, String> {
        let value = toml_span::parse(content).map_err(|e| e.to_string())?;

        let root = match value.as_ref() {
            ValueInner::Table(t) => t,
            _ => return Err("expected a TOML table at root".to_string()),
        };

        let mut cfg = RestConfig::default();

        if let Some(v) = root.get("listen_addr") {
            match v.as_ref() {
                ValueInner::String(s) => cfg.listen_addr = s.to_string(),
                _ => return Err("listen_addr: expected string".to_string()),
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
        if let Some(v) = root.get("blocked_status_code") {
            match v.as_ref() {
                ValueInner::Integer(n) => cfg.blocked_status_code = *n as u16,
                _ => return Err("blocked_status_code: expected integer".to_string()),
            }
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_listen_addr_is_localhost_8080() {
        assert_eq!(RestConfig::default().listen_addr, "127.0.0.1:8080");
    }

    #[test]
    fn default_config_file_is_etc_dgaard() {
        assert_eq!(RestConfig::default().config_file, "/etc/dgaard/dgaard.toml");
    }

    #[test]
    fn default_log_level_is_info() {
        assert_eq!(RestConfig::default().log_level, "info");
    }

    #[test]
    fn default_blocked_status_code_is_200() {
        assert_eq!(RestConfig::default().blocked_status_code, 200);
    }

    #[test]
    fn load_partial_toml_applies_defaults_for_missing_fields() {
        let toml = r#"listen_addr = "0.0.0.0:9090""#;
        let cfg = RestConfig::load(toml).unwrap();
        assert_eq!(cfg.listen_addr, "0.0.0.0:9090");
        assert_eq!(cfg.config_file, "/etc/dgaard/dgaard.toml");
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.blocked_status_code, 200);
    }

    #[test]
    fn load_full_toml_overrides_all_fields() {
        let toml = r#"
listen_addr = "0.0.0.0:8443"
config_file = "/etc/custom/engine.toml"
log_level = "debug"
blocked_status_code = 403
"#;
        let cfg = RestConfig::load(toml).unwrap();
        assert_eq!(cfg.listen_addr, "0.0.0.0:8443");
        assert_eq!(cfg.config_file, "/etc/custom/engine.toml");
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.blocked_status_code, 403);
    }

    #[test]
    fn load_invalid_toml_returns_error() {
        assert!(RestConfig::load("not = [valid toml").is_err());
    }
}
