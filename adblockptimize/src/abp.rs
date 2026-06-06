use crate::{error::ListError, model::Rule};

/// Extract clean domain from ABP domain pattern like `||example.com^`
/// Returns the domain without `||` prefix and `^` suffix
fn extract_domain_from_abp(pattern: &str) -> Option<&str> {
    let domain = pattern.strip_prefix("||")?;
    // Split on ^ and take the first part (the domain)
    let domain = domain.split('^').next()?;
    if domain.is_empty() {
        return None;
    }
    Some(domain)
}

pub fn parse_abp_line(line: &str) -> Result<Rule, ListError<'_>> {
    let mut input = line.trim();

    // 1. Check if it is a whitelist (@@) or a blacklist
    let is_whitelist = input.starts_with("@@");
    if is_whitelist {
        input = &input[2..];
    }

    // 2. Strip options (everything after '$')
    if let Some(pos) = input.find('$') {
        input = &input[..pos];
    }

    // 3. Identify pattern type and build the appropriate Rule variant
    let rule = if input.starts_with('/') && input.ends_with('/') && input.len() > 2 {
        // Regex pattern: /pattern/
        let pattern = &input[1..input.len() - 1];
        if pattern.is_empty() {
            return Err(ListError::ParseError(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty ABP regex pattern"),
                line,
                "abp",
            ));
        }
        if is_whitelist {
            Rule::Whitelist(pattern.to_string())
        } else {
            Rule::NetworkRegex(pattern.to_string())
        }
    } else if input.contains('*') {
        // Wildcard pattern: contains *
        if input.is_empty() {
            return Err(ListError::ParseError(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty ABP pattern"),
                line,
                "abp",
            ));
        }
        if is_whitelist {
            Rule::Whitelist(input.to_string())
        } else {
            Rule::NetworkWildcard(input.to_string())
        }
    } else {
        // Simple domain rule: ||domain.com^ -> extract clean domain; fallback to input as-is
        let value = extract_domain_from_abp(input).unwrap_or(input);
        if value.is_empty() {
            return Err(ListError::ParseError(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty ABP pattern"),
                line,
                "abp",
            ));
        }
        if is_whitelist {
            Rule::Whitelist(value.to_string())
        } else {
            Rule::NetworkDomain(value.to_string())
        }
    };

    Ok(rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Domain rules ──────────────────────────────────────────────────────────

    #[test]
    fn parse_standard_domain_rule() {
        let rule = parse_abp_line("||example.com^").unwrap();
        assert_eq!(rule, Rule::NetworkDomain("example.com".to_string()));
    }

    #[test]
    fn parse_domain_rule_with_options_strips_options() {
        let rule = parse_abp_line("||ads.example.com^$third-party").unwrap();
        assert_eq!(rule, Rule::NetworkDomain("ads.example.com".to_string()));
    }

    #[test]
    fn parse_domain_rule_with_path_keeps_domain_only() {
        // The '^' splits on first occurrence so path is dropped
        let rule = parse_abp_line("||example.com^/path").unwrap();
        assert_eq!(rule, Rule::NetworkDomain("example.com".to_string()));
    }

    #[test]
    fn parse_plain_domain_without_pipes_falls_through_to_input() {
        let rule = parse_abp_line("example.com").unwrap();
        // No "||" prefix, no wildcard, no regex → uses input as-is
        assert_eq!(rule, Rule::NetworkDomain("example.com".to_string()));
    }

    // ── Whitelist rules ───────────────────────────────────────────────────────

    #[test]
    fn parse_whitelist_domain_rule() {
        let rule = parse_abp_line("@@||safe.example.com^").unwrap();
        assert_eq!(rule, Rule::Whitelist("safe.example.com".to_string()));
    }

    #[test]
    fn parse_whitelist_regex_rule() {
        let rule = parse_abp_line("@@/safe-pattern/").unwrap();
        assert_eq!(rule, Rule::Whitelist("safe-pattern".to_string()));
    }

    #[test]
    fn parse_whitelist_with_options() {
        let rule = parse_abp_line("@@||safe.com^$document").unwrap();
        assert_eq!(rule, Rule::Whitelist("safe.com".to_string()));
    }

    // ── Regex rules ───────────────────────────────────────────────────────────

    #[test]
    fn parse_regex_rule() {
        let rule = parse_abp_line("/^ads\\.example\\.com/").unwrap();
        assert_eq!(rule, Rule::NetworkRegex("^ads\\.example\\.com".to_string()));
    }

    #[test]
    fn parse_slash_slash_treated_as_plain_domain() {
        // "//" has len == 2 which does not satisfy the `> 2` regex guard,
        // so it falls through to the plain domain branch.
        let result = parse_abp_line("//");
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Rule::NetworkDomain(_)));
    }

    // ── Wildcard rules ────────────────────────────────────────────────────────

    #[test]
    fn parse_wildcard_rule() {
        let rule = parse_abp_line("||*.ads.example.com^").unwrap();
        assert_eq!(
            rule,
            Rule::NetworkWildcard("||*.ads.example.com^".to_string())
        );
    }

    #[test]
    fn parse_wildcard_whitelist() {
        let rule = parse_abp_line("@@||*.safe.com^").unwrap();
        assert_eq!(rule, Rule::Whitelist("||*.safe.com^".to_string()));
    }

    // ── Trimming / whitespace ─────────────────────────────────────────────────

    #[test]
    fn parse_rule_with_leading_trailing_whitespace() {
        let rule = parse_abp_line("  ||example.com^  ").unwrap();
        assert_eq!(rule, Rule::NetworkDomain("example.com".to_string()));
    }
}
