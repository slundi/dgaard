use std::str::FromStr;

use hickory_resolver::Name;

use crate::{error::ListError, model::ListFormat};

/// Detect format type from a line
pub fn detect_format(line: &str) -> ListFormat {
    if line.starts_with("server=/") || line.starts_with("address=/") {
        ListFormat::Dnsmasq
    } else if line.starts_with("0.0.0.0 ")
        || line.starts_with("127.0.0.1 ")
        || line.starts_with(":: ")
    {
        ListFormat::Hosts
    } else if line.starts_with("||") || line.starts_with("@@||") {
        // ABP domain rules: ||example.com^ or @@||example.com^
        ListFormat::Abp
    } else if line.starts_with('/') && line.len() > 2 && line[1..].contains('/') {
        // ABP regex rules: /pattern/
        ListFormat::Abp
    } else if !line.contains(' ') && !line.contains('/') {
        ListFormat::Plain
    } else {
        ListFormat::Unknown
    }
}

/// Parse hosts format line: "0.0.0.0 domain.com" or "127.0.0.1 domain.com" or ":: domain.com"
pub fn parse_host_line(line: &str) -> Result<(String, u8), ListError<'_>> {
    // Split by whitespace and get the domain (second part)
    let domain = line.split_whitespace().nth(1).ok_or_else(|| {
        ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "No domain found"),
            line,
            "host",
        )
    })?;

    // Validate domain
    Name::from_str(domain).map_err(|e| ListError::InvalidDomain(e, domain))?;

    Ok((domain.to_string(), 0))
}

/// Parse dnsmasq format line: "server=/domain.com/" or "address=/domain.com/127.0.0.1"
pub fn parse_dnsmasq_line(line: &str) -> Result<(String, u8), ListError<'_>> {
    let domain = line.split('/').nth(1).ok_or_else(|| {
        ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid dnsmasq format"),
            line,
            "dnsmasq",
        )
    })?;

    if domain.is_empty() {
        return Err(ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty domain"),
            line,
            "dnsmasq",
        ));
    }

    Ok((domain.to_string(), 0))
}

/// Parse plain domain format: just the domain name with no IP prefix
pub fn parse_plain_domain(line: &str) -> Result<(String, u8), ListError<'_>> {
    let domain = line.trim();

    if domain.is_empty() {
        return Err(ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty domain"),
            line,
            "plain",
        ));
    }

    // Validate domain
    Name::from_str(domain).map_err(|e| ListError::InvalidDomain(e, domain))?;

    Ok((domain.to_string(), 0))
}
