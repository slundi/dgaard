use dgaard::{Action, config::Config};
use serde::Deserialize;

use crate::dga::{calculate_entropy, calculate_entropy_fast};
use arc_swap::ArcSwap;
use fst::Set as FstSet;
use lru::LruCache;
use std::{
    collections::HashSet,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum FilterStage {
    Whitelist,
    /// | Region | Language | Example Allowed Chars | Example Domain |
    /// |:-------|:--------:|:---------------------:|:---------------|
    /// | Western Europe | FR, DE, ES, IT | `à, â, æ, ç, é, è, ê, ë, î, ï, ô, œ, ù, û, ü, ÿ, `ß` | `bibliothèque.fr` |
    BlockIDN,
    HotCache,
    StaticBlock,
    SuffixMatch,
    Heuristics,
    Upstream,
}

pub struct Resolver {
    /// The immutable configuration (cloned from main)
    pub config: Arc<Config>,

    /// The "Live" rule sets, wrapped in ArcSwap for zero-downtime updates
    pub rules: ArcSwap<ResolverRules>,

    /// Hot Cache for frequently accessed domains (LRU requires Mutex for mutability)
    pub hot_cache: Mutex<LruCache<String, std::net::Ipv4Addr>>,
}

/// This internal struct holds the actual filter data.
/// When the updater finishes, it creates a NEW version of this and "swaps" it.
pub struct ResolverRules {
    /// Fast-path Whitelist (Exact matches)
    pub whitelist: HashSet<u64>, // Storing xxh64 hashes to save RAM

    /// Blacklist Bloom Filter (For millions of domains with tiny RAM footprint)
    pub block_bloom: Bloom<u64>,

    /// Suffix/Wildcard Matcher (Finite State Transducer)
    /// Excellent for *.ru, *.top, or ad-server patterns
    pub wildcards: FstSet<Vec<u8>>,

    /// Extracted ABP Rules
    pub abp: AbpFilter,

    /// Newly Registered Domains (NRD)
    /// Often stored as a separate Bloom filter updated daily
    pub nrd_filter: Bloom<u64>,
}

pub fn is_dga_suspicious(domain: &str, threshold: f32, min_len: usize, use_fast: bool) -> bool {
    // Only run entropy on the Second Level Domain (SLD)
    // "sub.example.com" -> check "example"
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return false;
    }

    let sld = parts[parts.len() - 2];

    if sld.len() < min_len {
        return false;
    }

    let entropy = if use_fast {
        calculate_entropy_fast(sld)
    } else {
        calculate_entropy(sld)
    };
    entropy > threshold
}

impl Resolver {
    pub async fn new(config: Arc<Config>) -> Self {
        // 1. Load your local lists from /etc/dgaard/...
        // 2. Build the Bloom Filter and FST
        let initial_rules = ResolverRules {
            whitelist: HashSet::new(), // Populate from file
            block_bloom: Bloom::new(0.01, config.memory.expected_total_domains),
            wildcards: FstSet::from_iter(Vec::<String>::new()).unwrap(),
            abp: AbpFilter::default(),
            nrd_filter: Bloom::new(0.01, 100_000),
        };

        Self {
            config,
            rules: ArcSwap::from_pointee(initial_rules),
            hot_cache: Mutex::new(LruCache::new(std::num::NonZeroUsize::new(1000).unwrap())),
        }
    }

    pub fn is_illegal_idn(&self, domain: &str) -> bool {
        if !self.config.server.block_idn {
            return false;
        }

        // 1. Check for Punycode prefix in any segment of the domain
        // (e.g., "sub.xn--apple.com")
        if domain.split('.').any(|part| part.starts_with("xn--")) {
            return true;
        }

        // 2. Check for raw non-ASCII characters
        // (In case the parser already decoded them)
        if !domain.is_ascii() {
            return true;
        }

        false
    }

    pub async fn resolve(&self, domain: &str, ip: [u8; 16]) -> Action {
        // We iterate through the stages defined in the config
        for stage in &self.config.server.pipeline {
            match stage {
                FilterStage::Whitelist => {
                    if self.is_whitelisted(domain) {
                        return Action::Allow;
                    }
                }
                FilterStage::BlockIDN => {
                    // Add this new stage
                    if self.is_illegal_idn(domain) {
                        return Action::Block;
                    }
                }
                FilterStage::HotCache => {
                    if let Some(ip) = self.cache.get(domain) {
                        return Action::Respond(ip);
                    }
                }
                FilterStage::StaticBlock => {
                    if self.is_blacklisted(domain) {
                        return Action::Block;
                    }
                }
                FilterStage::Heuristics => {
                    if self.check_dga(domain) {
                        return Action::Block;
                    }
                }
                FilterStage::Upstream => {
                    return Action::ProxyToUpstream;
                }
                // Add SuffixMatch etc...
                _ => continue,
            }
        }

        // Safety fallback if the user forgot "Upstream"
        Action::ProxyToUpstream
    }
}

pub async fn resolve(&self, domain: &str, client_ip: [u8; 16]) -> Action {
    // 1. Static Whitelist (Includes ABP Exceptions)
    if self.whitelist.contains(domain) || self.abp.exceptions.contains(domain) {
        return Action::Allow;
    }

    // 2. Favorites / Hot Cache
    if let Some(cached_ip) = self.hot_cache.get(domain) {
        return Action::Respond(cached_ip);
    }

    // 3. Domain Blocklists (Includes extracted ABP rules)
    if self.blocklist.contains(domain) || self.abp.blocked_domains.contains(domain) {
        return Action::Block;
    }

    // 4. Wildcard / Suffix Checks (e.g., *.xyz)
    if self.is_wildcard_blocked(domain) {
        return Action::Block;
    }

    // 5. Heuristics (The "Expensive" stuff)
    let hash = calculate_xxh64(domain);
    if self.config.dga.enabled && calculate_entropy(domain) > self.config.dga.threshold {
        self.log_event(domain, hash, RULE_ID_DGA, client_ip).await;
        return Action::Block;
    }

    // 6. Final Upstream Resolution
    Action::ProxyToUpstream
}
