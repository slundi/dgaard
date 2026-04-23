use std::{path::PathBuf, str::FromStr};

use url::Url;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ListFormat {
    Hosts,
    Dnsmasq,
    Plain,
    Abp,
    Unknown,
}

impl FromStr for ListFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hosts" => Ok(ListFormat::Hosts),
            "dnsmasq" => Ok(ListFormat::Dnsmasq),
            "plain" => Ok(ListFormat::Plain),
            "abp" => Ok(ListFormat::Abp),
            _ => Err(format!(
                "unknown format '{s}', expected: hosts, dnsmasq, plain, abp"
            )),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Resource {
    HttpUrl(Url),
    FilePath(PathBuf),
}
