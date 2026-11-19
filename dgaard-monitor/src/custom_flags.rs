//! Labels of the custom `StatBlockReason` bits (16–31), read from the dgaard
//! engine config named by `[input] engine_config_path`.
//!
//! Only `[[security.custom_flags]]` `bit` and `code` are read; the rest of
//! the engine config is ignored, so the monitor neither depends on the
//! engine crate nor fails on engine settings it does not know.

use std::collections::HashSet;

use toml_span::value::{Table, ValueInner};

/// Read the custom flag labels from the engine config at `path`.
pub fn load(path: &str) -> Result<Vec<(u8, String)>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse(&content)
}

/// Extract `(bit, code)` for every `[[security.custom_flags]]` entry, with
/// the engine's rules: bit in 16–31 and unique, code present.
pub fn parse(content: &str) -> Result<Vec<(u8, String)>, String> {
    let root = toml_span::parse(content).map_err(|e| format!("TOML syntax error: {e}"))?;
    let ValueInner::Table(root) = root.as_ref() else {
        return Err("not a TOML table".to_string());
    };
    let Some(security) = table(root, "security")? else {
        return Ok(Vec::new());
    };
    let Some(entries) = security.get("custom_flags") else {
        return Ok(Vec::new());
    };
    let ValueInner::Array(entries) = entries.as_ref() else {
        return Err("security.custom_flags must be an array of tables".to_string());
    };

    let mut labels = Vec::with_capacity(entries.len());
    let mut seen = HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let ValueInner::Table(entry) = entry.as_ref() else {
            return Err(format!("security.custom_flags[{index}] must be a table"));
        };
        let bit = match entry.get("bit").map(|v| v.as_ref()) {
            Some(ValueInner::Integer(bit)) if (16..=31).contains(bit) => *bit as u8,
            Some(ValueInner::Integer(bit)) => {
                return Err(format!(
                    "security.custom_flags[{index}].bit must be in 16–31, got {bit}"
                ));
            }
            _ => return Err(format!("security.custom_flags[{index}].bit is missing")),
        };
        let code = match entry.get("code").map(|v| v.as_ref()) {
            Some(ValueInner::String(code)) => code.to_string(),
            _ => return Err(format!("security.custom_flags[{index}].code is missing")),
        };
        // The code ends up in logs, JSON and SIEM lines.
        if code.is_empty() || code.chars().any(char::is_control) {
            return Err(format!(
                "security.custom_flags[{index}].code must be non-empty, without control characters"
            ));
        }
        if !seen.insert(bit) {
            return Err(format!("duplicate custom flag bit {bit}"));
        }
        labels.push((bit, code));
    }
    Ok(labels)
}

fn table<'a>(parent: &'a Table<'a>, key: &str) -> Result<Option<&'a Table<'a>>, String> {
    match parent.get(key).map(|v| v.as_ref()) {
        None => Ok(None),
        Some(ValueInner::Table(t)) => Ok(Some(t)),
        Some(_) => Err(format!("{key} must be a table")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_bits_and_codes_only() {
        let labels = parse(
            r#"
[server]
listen = "0.0.0.0:53"

[security]
some_future_setting = true

[[security.custom_flags]]
bit = 16
code = "AI_GENERATED"
name = "AI-generated domain"
suspicious_score = 3
list_path = ["/etc/dgaard/ai.txt"]

[[security.custom_flags]]
bit = 31
code = "CORP_FEED"
"#,
        )
        .unwrap();
        assert_eq!(
            labels,
            [
                (16, "AI_GENERATED".to_string()),
                (31, "CORP_FEED".to_string())
            ]
        );
    }

    #[test]
    fn no_custom_flags_is_empty() {
        assert!(parse("").unwrap().is_empty());
        assert!(parse("[security]\n").unwrap().is_empty());
        assert!(parse("[server]\nlisten = \"x\"\n").unwrap().is_empty());
    }

    #[test]
    fn invalid_entries_are_rejected() {
        for (content, needle) in [
            (
                "[[security.custom_flags]]\nbit = 15\ncode = \"X\"\n",
                "16–31",
            ),
            (
                "[[security.custom_flags]]\nbit = 32\ncode = \"X\"\n",
                "16–31",
            ),
            (
                "[[security.custom_flags]]\ncode = \"X\"\n",
                "bit is missing",
            ),
            ("[[security.custom_flags]]\nbit = 20\n", "code is missing"),
            (
                "[[security.custom_flags]]\nbit = 20\ncode = \"\"\n",
                "non-empty",
            ),
            (
                "[[security.custom_flags]]\nbit = 20\ncode = \"A\\nB\"\n",
                "control characters",
            ),
            (
                "[[security.custom_flags]]\nbit = 20\ncode = \"A\"\n[[security.custom_flags]]\nbit = 20\ncode = \"B\"\n",
                "duplicate",
            ),
            ("security = 1\n", "must be a table"),
            ("this is not toml ][", "syntax"),
        ] {
            let err = parse(content).unwrap_err();
            assert!(err.contains(needle), "{content:?}: {err}");
        }
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(load("/nonexistent/dgaard.toml").is_err());
    }
}
