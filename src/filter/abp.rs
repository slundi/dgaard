//! Adblock rules
//! * `||example.com^`: domain and all its sub domains
//! * `@@||example.com^`: whitelist for this domain
//! * `/regex/`: regular expression
//! * `*`: universal wildcard, can be anywhere in the domain

use std::{collections::HashSet, sync::atomic::Ordering};

use crate::{
    GLOBAL_SEED,
    filter::{IS_REGEX, IS_WHITELIST, IS_WILDCARD, ListError},
    model::RawDomainEntry,
    utils::count_dots,
};

pub fn parse_abp_line(line: &str) -> Result<RawDomainEntry, ListError<'_>> {
    let mut input = line.trim();

    // 1. Check if it is a whitelist (@@) or a blacklist
    let mut flags = if input.starts_with("@@") {
        input = &input[2..];
        IS_WHITELIST
    } else {
        0
    };

    // 2. Cleanup option (ignore following '$')
    if let Some(pos) = input.find('$') {
        input = &input[..pos];
    }

    // 3. Identify pattern type
    let pattern = if input.starts_with('/') && input.ends_with('/') && input.len() > 2 {
        // this is a regex
        flags |= IS_REGEX;
        &input[1..input.len() - 1]
    } else {
        // it is a domain or a wildcard (ex: ||example.com^ ou *doubleclick*)
        // keep symbols || and ^ because they can be useful for later matching
        if input.contains('*') {
            // TODO: improve because we may have `*.example.com` so it needs to be treated as wildcard.
            // But for `some.*.thing.com` or `facebook*.com` it will be a dedicated wildcard processing
            flags |= IS_WILDCARD;
        }
        input
    };

    if pattern.is_empty() {
        return Err(ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty ABP pattern"),
            line,
            "abp",
        ));
    }

    let hash = twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), line.as_bytes());

    Ok(RawDomainEntry {
        hash,
        value: pattern.to_string(),
        depth: count_dots(pattern),
        flags,
    })
}

pub struct AbpFilter {
    pub blocked_domains: HashSet<String>,
    pub exceptions: HashSet<String>,
}

impl AbpFilter {
    pub fn parse_line(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.contains("##") {
            return; // Skip comments and cosmetic rules
        }

        if line.starts_with("@@||") {
            // Exception rule: @@||example.com^
            if let Some(domain) = line.strip_prefix("@@||").and_then(|s| s.split('^').next()) {
                self.exceptions.insert(domain.to_string());
            }
        } else if line.starts_with("||") {
            // Block rule: ||example.com^
            if let Some(domain) = line.strip_prefix("||").and_then(|s| s.split('^').next()) {
                self.blocked_domains.insert(domain.to_string());
            }
        }
    }
}
