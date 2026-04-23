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
