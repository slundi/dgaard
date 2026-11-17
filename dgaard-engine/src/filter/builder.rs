//! Single construction path for a [`FilterEngine`].
//!
//! Every engine — built from local files ([`FilterEngine::build_from_files`])
//! or from lists a host downloaded itself (the `dgaard` daemon) — goes
//! through [`FilterEngineBuilder`]: lists are added as files or as text, in
//! the order given by [`list_sources`], then [`FilterEngineBuilder::build`]
//! applies every config-driven filter. Hosts only add their own transport.

use std::collections::{HashMap, HashSet};

use regex::Regex;

use crate::{
    config::Config,
    filter::{
        LoadFilter,
        engine::{FilterEngine, GeoipFileMeta},
        load_list_content, load_list_file,
    },
    model::{DomainEntry, DomainEntryFlags},
};

/// Role of a list source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    /// Entries override every other filter.
    Whitelist,
    /// Newly registered domains (scoring signal).
    Nrd,
    /// Blocked entries.
    Blacklist,
}

impl ListKind {
    fn flags(self) -> DomainEntryFlags {
        match self {
            Self::Whitelist => DomainEntryFlags::WHITELIST,
            Self::Nrd => DomainEntryFlags::NRD,
            Self::Blacklist => DomainEntryFlags::NONE,
        }
    }

    /// Whitelist entries always survive; blacklist and NRD entries go
    /// through the load-time filter.
    fn filtered(self) -> bool {
        !matches!(self, Self::Whitelist)
    }

    /// Name used in log messages.
    pub fn label(self) -> &'static str {
        match self {
            Self::Whitelist => "whitelist",
            Self::Nrd => "NRD list",
            Self::Blacklist => "blacklist",
        }
    }
}

/// Every list source of `[sources]` with its role, in merge order:
/// whitelists, the NRD list, then blacklists. All hosts follow this order,
/// so the same content always yields the same engine.
pub fn list_sources(config: &Config) -> Vec<(&str, ListKind)> {
    let sources = &config.sources;
    let mut plan: Vec<(&str, ListKind)> = sources
        .whitelists
        .iter()
        .map(|s| (s.as_str(), ListKind::Whitelist))
        .collect();
    if !sources.nrd_list_path.is_empty() {
        plan.push((sources.nrd_list_path.as_str(), ListKind::Nrd));
    }
    plan.extend(
        sources
            .blacklists
            .iter()
            .map(|s| (s.as_str(), ListKind::Blacklist)),
    );
    plan
}

/// A built engine and the by-products of loading its lists.
pub struct BuiltFilter {
    pub engine: FilterEngine,
    /// Hash → domain for every exact entry (see `host_index`).
    pub host_index: HashMap<u64, String>,
    /// ABP cosmetic rules a DNS filter cannot apply.
    pub browser_rules: Vec<String>,
}

/// Accumulates list entries, then builds the engine with every
/// config-driven filter (TLD, lexical, ASN, GeoIP, custom flags).
pub struct FilterEngineBuilder<'a> {
    config: &'a Config,
    seed: u64,
    load_filter: LoadFilter,
    fast_map: HashMap<u64, (u8, Box<str>)>,
    hierarchical_list: Vec<DomainEntry>,
    wildcard_patterns: Vec<String>,
    regex_pool: Vec<Regex>,
    host_index: HashMap<u64, String>,
    browser_rules: Vec<String>,
    previous_geoip_meta: Option<GeoipFileMeta>,
}

impl<'a> FilterEngineBuilder<'a> {
    pub fn new(config: &'a Config, seed: u64) -> Self {
        Self {
            config,
            seed,
            // Drops blacklist / NRD entries that a hard query-time block
            // (structural sanity, TLD exclude, IDN) already covers.
            load_filter: LoadFilter::from_config(config, seed),
            fast_map: HashMap::new(),
            hierarchical_list: Vec::new(),
            wildcard_patterns: Vec::new(),
            regex_pool: Vec::new(),
            host_index: HashMap::new(),
            browser_rules: Vec::new(),
            previous_geoip_meta: None,
        }
    }

    /// Carry over state from the engine being replaced: the GeoIP database
    /// snapshot, so an in-place write of the file between two reloads is
    /// detected and reported.
    pub fn with_previous(mut self, previous: &FilterEngine) -> Self {
        self.previous_geoip_meta = previous.geoip_file_meta.clone();
        self
    }

    /// Merge a list given as text (e.g. downloaded by the host).
    pub fn add_content(&mut self, content: &str, kind: ListKind) {
        load_list_content(
            content,
            kind.flags(),
            self.seed,
            &mut self.fast_map,
            &mut self.hierarchical_list,
            &mut self.wildcard_patterns,
            &mut self.regex_pool,
            &mut self.host_index,
            &mut self.browser_rules,
            kind.filtered().then_some(&self.load_filter),
        );
    }

    /// Merge a list file, streamed from disk.
    pub fn add_file(&mut self, path: &str, kind: ListKind) -> std::io::Result<()> {
        load_list_file(
            path,
            kind.flags(),
            self.seed,
            &mut self.fast_map,
            &mut self.hierarchical_list,
            &mut self.wildcard_patterns,
            &mut self.regex_pool,
            &mut self.host_index,
            &mut self.browser_rules,
            kind.filtered().then_some(&self.load_filter),
        )
    }

    /// Assemble the engine and apply every config-driven filter.
    pub fn build(self) -> BuiltFilter {
        let mut hierarchical_list = self.hierarchical_list;
        hierarchical_list.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.hash.cmp(&b.hash)));
        hierarchical_list.dedup();
        let mut wildcard_patterns = self.wildcard_patterns;
        wildcard_patterns.sort();
        wildcard_patterns.dedup();

        let mut engine = FilterEngine {
            fast_map: self.fast_map,
            hierarchical_list,
            regex_pool: self.regex_pool,
            wildcard_patterns,
            keyword_automaton: None,
            keyword_patterns: Vec::new(),
            suspicious_tld_hashes: HashSet::new(),
            lexical_strict: true,
            blocked_asn_v4: Vec::new(),
            blocked_asn_v6: Vec::new(),
            geoip_reader: None,
            geoip_file_meta: self.previous_geoip_meta,
            suspicious_country_codes: HashSet::new(),
            suspicious_country_score: 3,
            custom_flag_maps: Vec::new(),
            seed: self.seed,
        };

        engine.load_tld_filters(self.config);
        // TLD entries were appended after the sort — restore the invariant
        // binary searches in the suffix matcher rely on.
        engine
            .hierarchical_list
            .sort_by(|a, b| a.depth.cmp(&b.depth).then(a.hash.cmp(&b.hash)));
        engine.load_lexical_filters(self.config);
        engine.load_asn_filters(self.config);
        engine.load_geoip_filter(self.config);
        engine.load_custom_flags(self.config);

        BuiltFilter {
            engine,
            host_index: self.host_index,
            browser_rules: self.browser_rules,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use tempfile::NamedTempFile;

    use super::*;
    use crate::config::CustomFlagConfig;

    const SEED: u64 = 42;

    fn hash(domain: &str) -> u64 {
        twox_hash::XxHash64::oneshot(SEED, domain.as_bytes())
    }

    fn temp_list(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    fn path_of(file: &NamedTempFile) -> String {
        file.path().to_str().unwrap().to_owned()
    }

    /// No list sources at all: tests add their own.
    fn empty_sources_config() -> Config {
        let mut config = Config::default();
        config.sources.blacklists = Vec::new();
        config.sources.whitelists = Vec::new();
        config.sources.nrd_list_path = String::new();
        config
    }

    #[test]
    fn list_sources_merge_order() {
        let mut config = empty_sources_config();
        config.sources.blacklists = vec!["b1".into(), "b2".into()];
        config.sources.whitelists = vec!["w1".into()];
        config.sources.nrd_list_path = "nrd".into();
        assert_eq!(
            list_sources(&config),
            [
                ("w1", ListKind::Whitelist),
                ("nrd", ListKind::Nrd),
                ("b1", ListKind::Blacklist),
                ("b2", ListKind::Blacklist),
            ]
        );
        config.sources.nrd_list_path = String::new();
        assert!(
            list_sources(&config)
                .iter()
                .all(|(_, kind)| *kind != ListKind::Nrd)
        );
    }

    #[test]
    fn content_and_file_sources_build_the_same_engine() {
        let config = empty_sources_config();
        let lists = [
            ("0.0.0.0 ads.com\n||tracker.net^\n", ListKind::Blacklist),
            ("safe.com\n", ListKind::Whitelist),
        ];

        let mut from_text = FilterEngineBuilder::new(&config, SEED);
        for (content, kind) in lists {
            from_text.add_content(content, kind);
        }
        let files: Vec<NamedTempFile> = lists
            .iter()
            .map(|(content, _)| temp_list(content))
            .collect();
        let mut from_files = FilterEngineBuilder::new(&config, SEED);
        for (file, (_, kind)) in files.iter().zip(lists) {
            from_files.add_file(&path_of(file), kind).unwrap();
        }

        let (text, file) = (from_text.build().engine, from_files.build().engine);
        assert_eq!(text.fast_map, file.fast_map);
        assert_eq!(text.hierarchical_list, file.hierarchical_list);
        assert_eq!(text.fast_map.len(), 3);
    }

    #[test]
    fn build_from_files_matches_the_builder() {
        let black = temp_list("0.0.0.0 ads.com\n||tracker.net^\n");
        let white = temp_list("safe.com\n");
        let mut config = empty_sources_config();
        config.sources.blacklists = vec![path_of(&black)];
        config.sources.whitelists = vec![path_of(&white)];

        let mut builder = FilterEngineBuilder::new(&config, SEED);
        for (path, kind) in list_sources(&config) {
            builder.add_file(path, kind).unwrap();
        }
        let built = builder.build().engine;
        let direct = FilterEngine::build_from_files(&config, SEED);
        assert_eq!(built.fast_map, direct.fast_map);
        assert_eq!(built.hierarchical_list, direct.hierarchical_list);
    }

    #[test]
    fn build_loads_custom_flags() {
        // Review E7: the daemon's own construction never loaded these.
        let flagged = temp_list("flagged.com\n# comment\n");
        let mut config = empty_sources_config();
        config.security.custom_flags = vec![CustomFlagConfig {
            bit: 16,
            code: "TEST".into(),
            name: "Test flag".into(),
            description: String::new(),
            suspicious_score: 4,
            list_path: vec![path_of(&flagged)],
        }];
        let engine = FilterEngineBuilder::new(&config, SEED).build().engine;
        assert_eq!(engine.custom_flag_maps.len(), 1);
        let (bit, score, map) = &engine.custom_flag_maps[0];
        assert_eq!((*bit, *score), (16, 4));
        assert!(map.contains_key(&hash("flagged.com")));
    }

    #[test]
    fn previous_geoip_snapshot_is_carried_over() {
        let config = empty_sources_config();
        let mut previous = FilterEngine::empty();
        previous.geoip_file_meta = Some(GeoipFileMeta {
            ino: 7,
            size: 1024,
            mtime: 1_700_000_000,
        });
        let carried = FilterEngineBuilder::new(&config, SEED)
            .with_previous(&previous)
            .build()
            .engine;
        let meta = carried.geoip_file_meta.expect("snapshot carried over");
        assert_eq!((meta.ino, meta.size, meta.mtime), (7, 1024, 1_700_000_000));

        let fresh = FilterEngineBuilder::new(&config, SEED).build().engine;
        assert!(fresh.geoip_file_meta.is_none());
    }

    #[test]
    fn load_filter_spares_whitelists_only() {
        // `.xyz` is excluded: blacklist entries there are redundant and
        // dropped at load time, whitelist entries must survive.
        let mut config = empty_sources_config();
        config.tld.exclude = vec!["xyz".into()];
        let mut builder = FilterEngineBuilder::new(&config, SEED);
        builder.add_content("blocked.xyz\n", ListKind::Blacklist);
        builder.add_content("allowed.xyz\n", ListKind::Whitelist);
        let engine = builder.build().engine;
        assert!(!engine.fast_map.contains_key(&hash("blocked.xyz")));
        assert!(engine.fast_map.contains_key(&hash("allowed.xyz")));
    }

    #[test]
    fn build_deduplicates_and_keeps_hierarchical_order() {
        let mut config = empty_sources_config();
        config.tld.exclude = vec!["zz".into()];
        let mut builder = FilterEngineBuilder::new(&config, SEED);
        builder.add_content(
            "||ads.com^\n||ads.com^\n||a.b.tracker.net^\n",
            ListKind::Blacklist,
        );
        let engine = builder.build().engine;
        let keys: Vec<(u8, u64)> = engine
            .hierarchical_list
            .iter()
            .map(|entry| (entry.depth, entry.hash))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(keys, sorted, "sorted by (depth, hash), no duplicates");
        assert_eq!(keys.len(), 3, "ads.com, a.b.tracker.net and the zz TLD");
    }
}
