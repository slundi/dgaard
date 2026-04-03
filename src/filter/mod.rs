mod abp;
mod bloom;
mod fst;

use core::sync::atomic::Ordering;
use hickory_resolver::{Name, proto::ProtoError};
use regex::Regex;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use thiserror::Error;

use crate::{
    CURRENT_ENGINE, GLOBAL_SEED,
    model::{DomainEntry, DomainEntryFlags, RawDomainEntry},
    utils::count_dots,
};

#[derive(Error, Debug)]
pub enum ListError<'a> {
    #[error("Invalid domain {1}: {0}")]
    InvalidDomain(#[source] ProtoError, &'a str),
    #[error("Failed to parse line: {1}, format: {2}. Internal error: {0}")]
    ParseError(#[source] std::io::Error, &'a str, &'a str),
}

pub fn parse_line<'a, F>(line: &'a str, parser: F) -> Result<RawDomainEntry, ListError<'a>>
where
    F: Fn(&'a str) -> Result<RawDomainEntry, ListError<'a>>,
{
    // common logic like trimming and ignoring comments
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        todo!();
    }

    parser(trimmed)
}

pub fn parse_host_line(line: &str) -> Result<RawDomainEntry, ListError<'_>> {
    let mut s = line.split('.');
    let domain = s.next_back().ok_or_else(|| {
        ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "No domain found"),
            line,
            "host",
        )
    })?;

    Name::from_str(domain).map_err(|e| ListError::InvalidDomain(e, domain))?;

    let hash = twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), line.as_bytes());

    Ok(RawDomainEntry {
        hash,
        value: domain.to_string(),
        flags: DomainEntryFlags::NONE,
        depth: count_dots(domain),
    })
}

// Example with (ex: dnsmasq format "address=/doubleclick.net/127.0.0.1")
pub fn parse_dnsmasq_line(line: &str) -> Result<RawDomainEntry, ListError<'_>> {
    // Logique simplifiée pour l'exemple
    let domain = line.split('/').nth(1).ok_or_else(|| {
        ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid dnsmasq format"),
            line,
            "dnsmasq",
        )
    })?;

    let hash = twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), line.as_bytes());

    Ok(RawDomainEntry {
        hash,
        value: domain.to_string(),
        flags: DomainEntryFlags::NONE,
        depth: count_dots(domain),
    })
}
