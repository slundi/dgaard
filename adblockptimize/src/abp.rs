use crate::{REGEX_RULE, WHITELIST, WILDCARD_RULE, error::ListError};

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

pub fn parse_abp_line(line: &str) -> Result<(String, u8), ListError<'_>> {
    let mut input = line.trim();

    // 1. Check if it is a whitelist (@@) or a blacklist
    let mut flags = if input.starts_with("@@") {
        input = &input[2..];
        WHITELIST
    } else {
        0
    };

    // 2. Cleanup option (ignore following '$')
    if let Some(pos) = input.find('$') {
        input = &input[..pos];
    }

    // 3. Identify pattern type and extract value
    let value = if input.starts_with('/') && input.ends_with('/') && input.len() > 2 {
        // Regex pattern: /pattern/
        flags |= REGEX_RULE;

        &input[1..input.len() - 1]
    } else if input.contains('*') {
        // Wildcard pattern: contains *
        flags |= WILDCARD_RULE;
        // For wildcards, keep the full pattern for later matching
        input
    } else if let Some(domain) = extract_domain_from_abp(input) {
        // Simple domain rule: ||domain.com^ -> extract clean domain
        domain
    } else {
        // Fallback: use the input as-is
        input
    };

    if value.is_empty() {
        return Err(ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty ABP pattern"),
            line,
            "abp",
        ));
    }

    Ok((value.to_string(), flags))
}
