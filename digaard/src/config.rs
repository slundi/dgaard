//! Optional TOML config file: sets defaults that CLI flags override.
//!
//! Search order for the config path:
//!   1. `--config PATH` on the command line (pre-pass, before bpaf).
//!   2. `$XDG_CONFIG_HOME/digaard/config.toml` (or `~/.config/digaard/config.toml`).
//!   3. None → all defaults come from bpaf `fallback()` values.
//!
//! Fields supported (all optional):
//! ```toml
//! default_server = "https://dns.quad9.net/dns-query"
//! # or a list, honoring --server-strategy:
//! default_servers = ["1.1.1.1", "9.9.9.9"]
//! default_transport = "udp"      # udp | tcp | tls | https | quic
//! default_format    = "pretty"   # pretty | text | json
//! color             = "auto"     # auto | always | never
//! timeout_ms        = 3000
//! retry             = 2
//! concurrency       = 16
//! ```

use toml_span::value::ValueInner;

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub servers: Vec<String>,
    pub transport: Option<String>,
    pub format: Option<String>,
    pub color: Option<String>,
    pub timeout_ms: Option<u64>,
    pub retry: Option<u32>,
    pub concurrency: Option<usize>,
}

/// Parse a config file's text. Returns a Config with only the fields the file
/// actually set.
pub fn parse(text: &str) -> Result<Config, String> {
    let value = toml_span::parse(text).map_err(|e| format!("config: {e}"))?;
    let root = match value.as_ref() {
        ValueInner::Table(t) => t,
        _ => return Err("config: expected a TOML table at root".to_string()),
    };

    let mut cfg = Config::default();

    if let Some(v) = root.get("default_server") {
        match v.as_ref() {
            ValueInner::String(s) => cfg.servers.push(s.to_string()),
            _ => return Err("default_server: expected string".to_string()),
        }
    }
    if let Some(v) = root.get("default_servers") {
        match v.as_ref() {
            ValueInner::Array(items) => {
                for item in items {
                    match item.as_ref() {
                        ValueInner::String(s) => cfg.servers.push(s.to_string()),
                        _ => return Err("default_servers: array must contain strings".to_string()),
                    }
                }
            }
            _ => return Err("default_servers: expected array".to_string()),
        }
    }

    cfg.transport = read_string(root, "default_transport")?;
    cfg.format = read_string(root, "default_format")?;
    cfg.color = read_string(root, "color")?;
    cfg.timeout_ms = read_u64(root, "timeout_ms")?;
    cfg.retry = read_u32(root, "retry")?;
    cfg.concurrency = read_usize(root, "concurrency")?;

    Ok(cfg)
}

/// Locate the config file to load.
///
/// Precedence: explicit `--config PATH` argument > `$XDG_CONFIG_HOME/digaard/config.toml`
/// > `~/.config/digaard/config.toml`.
pub fn default_path() -> Option<std::path::PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Some(std::path::PathBuf::from(xdg).join("digaard/config.toml"));
    }
    let home = std::env::var("HOME").ok()?;
    Some(std::path::PathBuf::from(home).join(".config/digaard/config.toml"))
}

/// Read and parse the config file at `path` if it exists. `None` for missing.
pub fn load_if_present(path: &std::path::Path) -> Result<Option<Config>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(parse(&text)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

fn read_string(root: &toml_span::value::Table<'_>, key: &str) -> Result<Option<String>, String> {
    match root.get(key) {
        None => Ok(None),
        Some(v) => match v.as_ref() {
            ValueInner::String(s) => Ok(Some(s.to_string())),
            _ => Err(format!("{key}: expected string")),
        },
    }
}

fn read_u64(root: &toml_span::value::Table<'_>, key: &str) -> Result<Option<u64>, String> {
    match root.get(key) {
        None => Ok(None),
        Some(v) => match v.as_ref() {
            ValueInner::Integer(i) if *i >= 0 => Ok(Some(*i as u64)),
            _ => Err(format!("{key}: expected non-negative integer")),
        },
    }
}

fn read_u32(root: &toml_span::value::Table<'_>, key: &str) -> Result<Option<u32>, String> {
    match read_u64(root, key)? {
        None => Ok(None),
        Some(n) if n <= u32::MAX as u64 => Ok(Some(n as u32)),
        Some(_) => Err(format!("{key}: value out of u32 range")),
    }
}

fn read_usize(root: &toml_span::value::Table<'_>, key: &str) -> Result<Option<usize>, String> {
    match read_u64(root, key)? {
        None => Ok(None),
        Some(n) if n <= usize::MAX as u64 => Ok(Some(n as usize)),
        Some(_) => Err(format!("{key}: value out of usize range")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_toml_yields_empty_config() {
        let cfg = parse("").unwrap();
        assert!(cfg.servers.is_empty());
        assert!(cfg.transport.is_none());
    }

    #[test]
    fn single_default_server() {
        let cfg = parse(r#"default_server = "1.1.1.1""#).unwrap();
        assert_eq!(cfg.servers, vec!["1.1.1.1"]);
    }

    #[test]
    fn multiple_default_servers() {
        let cfg = parse(
            r#"
                default_servers = ["1.1.1.1", "9.9.9.9"]
            "#,
        )
        .unwrap();
        assert_eq!(cfg.servers, vec!["1.1.1.1", "9.9.9.9"]);
    }

    #[test]
    fn all_scalar_fields() {
        let cfg = parse(
            r#"
                default_transport = "https"
                default_format = "json"
                color = "never"
                timeout_ms = 3000
                retry = 5
                concurrency = 16
            "#,
        )
        .unwrap();
        assert_eq!(cfg.transport.as_deref(), Some("https"));
        assert_eq!(cfg.format.as_deref(), Some("json"));
        assert_eq!(cfg.color.as_deref(), Some("never"));
        assert_eq!(cfg.timeout_ms, Some(3000));
        assert_eq!(cfg.retry, Some(5));
        assert_eq!(cfg.concurrency, Some(16));
    }

    #[test]
    fn rejects_negative_timeout() {
        let err = parse("timeout_ms = -1").unwrap_err();
        assert!(err.contains("timeout_ms"));
    }

    #[test]
    fn rejects_wrong_type() {
        let err = parse(r#"default_server = 42"#).unwrap_err();
        assert!(err.contains("default_server"));
    }

    #[test]
    fn rejects_non_table_root() {
        let err = parse("just_a_value = true").ok(); // this IS a table actually
        assert!(err.is_some());
    }
}
