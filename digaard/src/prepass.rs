//! Argv pre-pass: rewrite `+foo` shortcuts, extract `--config PATH`, and prepend
//! config-file-derived defaults so user CLI tokens always override.

use crate::config::Config;

/// `+foo` → canonical flag mapping. Add here as new shortcuts appear.
const SHORTCUTS: &[(&str, &[&str])] = &[
    ("+short", &["--short"]),
    ("+dnssec", &["--dnssec"]),
    ("+tcp", &["--tcp"]),
    ("+nord", &["--no-rd"]),
    ("+adflag", &["--ad"]),
    ("+cdflag", &["--cd"]),
    // +trace is deferred (M6/M7 note: iterative trace not yet implemented).
];

/// Rewrite `+foo` tokens into their canonical `--foo` equivalents.
///
/// Unknown `+xyz` tokens are left as-is so bpaf can produce a clean error.
pub fn expand_shortcuts(argv: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    for token in argv {
        if let Some(mapped) = SHORTCUTS.iter().find(|(k, _)| *k == token) {
            out.extend(mapped.1.iter().map(|s| s.to_string()));
        } else {
            out.push(token);
        }
    }
    out
}

/// Extract the value of the first `--config PATH` (or `--config=PATH`) in argv,
/// returning the value AND a new argv with the flag removed. If not present,
/// returns `(None, unchanged_argv)`.
pub fn take_config_flag(argv: Vec<String>) -> (Option<String>, Vec<String>) {
    let mut out = Vec::with_capacity(argv.len());
    let mut path: Option<String> = None;
    let mut iter = argv.into_iter();
    while let Some(tok) = iter.next() {
        if path.is_none() {
            if tok == "--config" {
                path = iter.next();
                continue;
            }
            if let Some(rest) = tok.strip_prefix("--config=") {
                path = Some(rest.to_string());
                continue;
            }
        }
        out.push(tok);
    }
    (path, out)
}

/// Prepend synthetic tokens for each config field whose corresponding CLI flag
/// is NOT already present in argv. User tokens end up later in the list, so
/// when bpaf encounters both, the user's value wins.
pub fn merge_config_defaults(argv: Vec<String>, cfg: &Config) -> Vec<String> {
    let has = |flags: &[&str]| {
        argv.iter()
            .any(|t| flags.iter().any(|f| starts_with_flag(t, f)))
    };

    let mut prepend: Vec<String> = Vec::new();

    if !has(&["-s", "--server"]) && !argv.iter().any(|t| t.starts_with('@')) {
        for s in &cfg.servers {
            prepend.push("-s".to_string());
            prepend.push(s.clone());
        }
    }
    if !has(&["--udp", "--tcp", "--tls", "--https", "--quic"])
        && let Some(t) = cfg.transport.as_deref()
    {
        match t.to_ascii_lowercase().as_str() {
            "udp" => prepend.push("--udp".to_string()),
            "tcp" => prepend.push("--tcp".to_string()),
            "tls" | "dot" => prepend.push("--tls".to_string()),
            "https" | "doh" => prepend.push("--https".to_string()),
            "quic" | "doq" => prepend.push("--quic".to_string()),
            other => log::warn!("config default_transport '{other}' unrecognized"),
        }
    }
    if !has(&["--text", "--json"])
        && let Some(f) = cfg.format.as_deref()
    {
        match f.to_ascii_lowercase().as_str() {
            "pretty" | "text" => prepend.push("--text".to_string()),
            "json" => prepend.push("--json".to_string()),
            other => log::warn!("config default_format '{other}' unrecognized"),
        }
    }
    if !has(&["--color"])
        && let Some(c) = cfg.color.as_deref()
    {
        prepend.push("--color".to_string());
        prepend.push(c.to_string());
    }
    if !has(&["--timeout"])
        && let Some(t) = cfg.timeout_ms
    {
        prepend.push("--timeout".to_string());
        prepend.push(t.to_string());
    }
    if !has(&["--retry"])
        && let Some(r) = cfg.retry
    {
        prepend.push("--retry".to_string());
        prepend.push(r.to_string());
    }
    if !has(&["-j", "--concurrency"])
        && let Some(n) = cfg.concurrency
    {
        prepend.push("--concurrency".to_string());
        prepend.push(n.to_string());
    }

    // Keep user tokens at the end so they override.
    prepend.extend(argv);
    prepend
}

fn starts_with_flag(token: &str, flag: &str) -> bool {
    if token == flag {
        return true;
    }
    // Match `--flag=value` style as well.
    if flag.starts_with("--") && token.starts_with(flag) {
        let rest = &token[flag.len()..];
        return rest.starts_with('=');
    }
    // Match `-xVAL` for short flags (e.g. `-s1.1.1.1`) — currently we treat
    // that conservatively: only exact-match.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_short_expands() {
        let out = expand_shortcuts(vec!["example.com".to_string(), "+short".to_string()]);
        assert_eq!(out, vec!["example.com", "--short"]);
    }

    #[test]
    fn multiple_shortcuts_expand() {
        let out = expand_shortcuts(vec![
            "+dnssec".to_string(),
            "example.com".to_string(),
            "+tcp".to_string(),
        ]);
        assert_eq!(out, vec!["--dnssec", "example.com", "--tcp"]);
    }

    #[test]
    fn unknown_plus_token_is_left_alone() {
        let out = expand_shortcuts(vec!["+xyz".to_string()]);
        assert_eq!(out, vec!["+xyz"]);
    }

    #[test]
    fn take_config_flag_extracts_value() {
        let (p, rest) = take_config_flag(vec![
            "example.com".to_string(),
            "--config".to_string(),
            "/etc/digaard.toml".to_string(),
            "--short".to_string(),
        ]);
        assert_eq!(p.as_deref(), Some("/etc/digaard.toml"));
        assert_eq!(rest, vec!["example.com", "--short"]);
    }

    #[test]
    fn take_config_flag_extracts_eq_form() {
        let (p, rest) = take_config_flag(vec![
            "--config=/tmp/c.toml".to_string(),
            "example.com".to_string(),
        ]);
        assert_eq!(p.as_deref(), Some("/tmp/c.toml"));
        assert_eq!(rest, vec!["example.com"]);
    }

    #[test]
    fn take_config_flag_absent() {
        let argv = vec!["example.com".to_string()];
        let (p, rest) = take_config_flag(argv.clone());
        assert!(p.is_none());
        assert_eq!(rest, argv);
    }

    #[test]
    fn merge_prepends_when_flag_missing() {
        let cfg = Config {
            servers: vec!["1.1.1.1".to_string()],
            timeout_ms: Some(3000),
            format: Some("json".to_string()),
            ..Config::default()
        };
        let out = merge_config_defaults(vec!["example.com".to_string()], &cfg);
        // Config-derived tokens come first, user tokens last.
        assert_eq!(
            &out[..out.len() - 1],
            &[
                "-s".to_string(),
                "1.1.1.1".to_string(),
                "--json".to_string(),
                "--timeout".to_string(),
                "3000".to_string(),
            ][..]
        );
        assert_eq!(out.last().unwrap(), "example.com");
    }

    #[test]
    fn merge_skips_when_cli_already_set() {
        let cfg = Config {
            servers: vec!["1.1.1.1".to_string()],
            timeout_ms: Some(3000),
            ..Config::default()
        };
        let argv = vec![
            "-s".to_string(),
            "8.8.8.8".to_string(),
            "example.com".to_string(),
        ];
        let out = merge_config_defaults(argv.clone(), &cfg);
        // -s already present → no -s prepended, but --timeout still prepended.
        assert!(
            !out[..out.len() - argv.len()]
                .iter()
                .any(|t| t == "-s" || t == "--server")
        );
        assert!(out.iter().any(|t| t == "--timeout"));
    }

    #[test]
    fn merge_skips_when_at_server_used() {
        let cfg = Config {
            servers: vec!["1.1.1.1".to_string()],
            ..Config::default()
        };
        let argv = vec!["@8.8.8.8".to_string(), "example.com".to_string()];
        let out = merge_config_defaults(argv, &cfg);
        assert!(!out.iter().any(|t| t == "-s"));
    }
}
