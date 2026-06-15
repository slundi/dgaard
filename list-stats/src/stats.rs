use std::collections::{HashMap, HashSet};

use dgaard_engine::{
    filter::load_list_content,
    model::{DomainEntry, DomainEntryFlags},
};
use regex::Regex;

use crate::model::{
    CategoryStats, EntryTypes, FreqEntry, GlobalStats, ListData, ListStats, OverlapEntry,
};

/// Parse raw list content into a ListData struct.
pub fn parse_list_data(name: &str, url: &str, category: &str, content: &str) -> ListData {
    let seed = 42u64;
    let mut fast_map: HashMap<u64, (u8, Box<str>)> = HashMap::new();
    let mut hierarchical_list: Vec<DomainEntry> = Vec::new();
    let mut wildcard_patterns: Vec<String> = Vec::new();
    let mut regex_pool: Vec<Regex> = Vec::new();
    let mut host_index: HashMap<u64, String> = HashMap::new();
    let mut browser_rules: Vec<String> = Vec::new();

    load_list_content(
        content,
        DomainEntryFlags::NONE,
        seed,
        &mut fast_map,
        &mut hierarchical_list,
        &mut wildcard_patterns,
        &mut regex_pool,
        &mut host_index,
        &mut browser_rules,
    );

    let domain_hashes: HashSet<u64> = host_index.keys().copied().collect();
    let domains: Vec<String> = host_index.into_values().collect();

    // Count wildcard entries from hierarchical_list (not just wildcard_patterns, which only
    // holds entries with partial glob segments like `ads*`; pure `*` segment wildcards like
    // `||*.example.com^` also carry WILDCARD flag but have data_idx == 0).
    let wildcard_count = hierarchical_list
        .iter()
        .filter(|e| {
            e.flags.contains(DomainEntryFlags::WILDCARD)
                && !e.flags.contains(DomainEntryFlags::REGEX)
        })
        .count();

    ListData {
        name: name.to_string(),
        url: url.to_string(),
        category: category.to_string(),
        domain_hashes,
        domains,
        wildcard_count,
        regex_count: regex_pool.len(),
    }
}

/// Extract the TLD from a domain (last dot-separated label, lowercased, prefixed with `.`).
fn extract_tld(domain: &str) -> &str {
    domain.rfind('.').map(|i| &domain[i..]).unwrap_or(domain)
}

/// Tokenize a domain for word-frequency analysis.
/// Split on `.`, `-`, `_`. Skip the last label (TLD) and tokens of length <= 1.
fn tokenize_domain(domain: &str) -> Vec<&str> {
    // Remove the last dot-separated segment (TLD)
    let without_tld = match domain.rfind('.') {
        Some(i) => &domain[..i],
        None => domain,
    };
    without_tld
        .split(['.', '-', '_'])
        .filter(|t| t.len() > 1)
        .collect()
}

/// Count frequencies in an iterator of string slices and return the top N sorted by count desc.
fn top_n(items: impl Iterator<Item = String>, n: usize) -> Vec<FreqEntry> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in items {
        *counts.entry(item).or_insert(0) += 1;
    }
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    sorted
        .into_iter()
        .take(n)
        .map(|(value, count)| FreqEntry { value, count })
        .collect()
}

/// Compute per-list statistics.
pub fn compute_list_stats(data: &ListData, top_n_count: usize) -> ListStats {
    let tlds = data.domains.iter().map(|d| extract_tld(d).to_lowercase());
    let top_tlds = top_n(tlds, top_n_count);

    let words = data
        .domains
        .iter()
        .flat_map(|d| tokenize_domain(d).into_iter().map(|t| t.to_lowercase()));
    let top_words = top_n(words, top_n_count);

    let count = data.domains.len() + data.wildcard_count + data.regex_count;

    ListStats {
        name: data.name.clone(),
        url: data.url.clone(),
        category: data.category.clone(),
        count,
        entry_types: EntryTypes {
            plain: data.domains.len(),
            wildcard: data.wildcard_count,
            regex: data.regex_count,
        },
        top_tlds,
        top_words,
    }
}

/// Compute global statistics across all lists.
pub fn compute_global_stats(all_data: &[ListData], top_n_count: usize) -> GlobalStats {
    let total_entries: usize = all_data
        .iter()
        .map(|d| d.domains.len() + d.wildcard_count + d.regex_count)
        .sum();

    let mut global_hashes: HashSet<u64> = HashSet::new();
    for d in all_data {
        global_hashes.extend(&d.domain_hashes);
    }
    let unique_entries = global_hashes.len();

    let all_tlds = all_data
        .iter()
        .flat_map(|d| d.domains.iter().map(|dom| extract_tld(dom).to_lowercase()));
    let top_tlds = top_n(all_tlds, top_n_count);

    let all_words = all_data.iter().flat_map(|d| {
        d.domains
            .iter()
            .flat_map(|dom| tokenize_domain(dom).into_iter().map(|t| t.to_lowercase()))
    });
    let top_words = top_n(all_words, top_n_count);

    let plain: usize = all_data.iter().map(|d| d.domains.len()).sum();
    let wildcard: usize = all_data.iter().map(|d| d.wildcard_count).sum();
    let regex: usize = all_data.iter().map(|d| d.regex_count).sum();

    GlobalStats {
        total_entries,
        unique_entries,
        top_tlds,
        top_words,
        entry_types: EntryTypes {
            plain,
            wildcard,
            regex,
        },
    }
}

/// Compute per-category rollup.
pub fn compute_categories(all_data: &[ListData]) -> Vec<CategoryStats> {
    let mut by_cat: HashMap<&str, (usize, HashSet<u64>, Vec<String>)> = HashMap::new();
    for d in all_data {
        let entry = by_cat.entry(&d.category).or_default();
        entry.0 += d.domains.len() + d.wildcard_count + d.regex_count;
        entry.1.extend(&d.domain_hashes);
        entry.2.push(d.name.clone());
    }
    let mut result: Vec<CategoryStats> = by_cat
        .into_iter()
        .map(|(cat, (total, hashes, lists))| CategoryStats {
            name: cat.to_string(),
            total,
            unique: hashes.len(),
            lists,
        })
        .collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

/// Compute pairwise overlap matrix across all lists.
/// Only emits pairs where shared > 0.
pub fn compute_overlap_matrix(all_data: &[ListData]) -> Vec<OverlapEntry> {
    let mut result = Vec::new();
    for i in 0..all_data.len() {
        for j in (i + 1)..all_data.len() {
            let a = &all_data[i];
            let b = &all_data[j];
            let shared = a.domain_hashes.intersection(&b.domain_hashes).count();
            if shared == 0 {
                continue;
            }
            let pct_a = if a.domain_hashes.is_empty() {
                0.0
            } else {
                shared as f32 / a.domain_hashes.len() as f32 * 100.0
            };
            let pct_b = if b.domain_hashes.is_empty() {
                0.0
            } else {
                shared as f32 / b.domain_hashes.len() as f32 * 100.0
            };
            result.push(OverlapEntry {
                list_a: a.name.clone(),
                list_b: b.name.clone(),
                shared,
                pct_a,
                pct_b,
            });
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data(name: &str, category: &str, content: &str) -> ListData {
        parse_list_data(name, "https://example.com/list.txt", category, content)
    }

    #[test]
    fn test_parse_list_data_plain() {
        let d = make_data("test", "ads", "example.com\nads.net\ntracker.org\n");
        assert_eq!(d.domains.len(), 3);
        assert_eq!(d.wildcard_count, 0);
        assert_eq!(d.regex_count, 0);
        assert_eq!(d.domain_hashes.len(), 3);
    }

    #[test]
    fn test_parse_list_data_abp_wildcard() {
        let d = make_data("test", "ads", "||*.ads.example.com^\n");
        assert_eq!(d.wildcard_count, 1);
        assert_eq!(d.domains.len(), 0);
    }

    #[test]
    fn test_top_tlds() {
        let d = make_data("test", "ads", "foo.com\nbar.com\nbaz.net\n");
        let stats = compute_list_stats(&d, 10);
        assert_eq!(stats.top_tlds[0].value, ".com");
        assert_eq!(stats.top_tlds[0].count, 2);
        assert_eq!(stats.top_tlds[1].value, ".net");
        assert_eq!(stats.top_tlds[1].count, 1);
    }

    #[test]
    fn test_top_words() {
        let d = make_data("test", "ads", "ads.example.com\ntracking.example.net\n");
        let stats = compute_list_stats(&d, 10);
        let words: Vec<&str> = stats.top_words.iter().map(|e| e.value.as_str()).collect();
        assert!(words.contains(&"ads"), "expected 'ads' in {words:?}");
        assert!(
            words.contains(&"example"),
            "expected 'example' in {words:?}"
        );
        assert!(
            words.contains(&"tracking"),
            "expected 'tracking' in {words:?}"
        );
    }

    #[test]
    fn test_overlap_matrix_same_list() {
        let content = "foo.com\nbar.net\n";
        let a = make_data("list-a", "ads", content);
        let b = make_data("list-b", "ads", content);
        let matrix = compute_overlap_matrix(&[a, b]);
        assert_eq!(matrix.len(), 1);
        let entry = &matrix[0];
        assert_eq!(entry.shared, 2);
        assert!((entry.pct_a - 100.0).abs() < 0.1);
        assert!((entry.pct_b - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_overlap_matrix_disjoint() {
        let a = make_data("list-a", "ads", "foo.com\n");
        let b = make_data("list-b", "ads", "bar.net\n");
        let matrix = compute_overlap_matrix(&[a, b]);
        assert!(matrix.is_empty(), "disjoint lists should have empty matrix");
    }

    #[test]
    fn test_global_unique() {
        let content = "same.com\n";
        let a = make_data("list-a", "ads", content);
        let b = make_data("list-b", "ads", content);
        let global = compute_global_stats(&[a, b], 10);
        assert_eq!(
            global.unique_entries, 1,
            "same domain in 2 lists counts once"
        );
        assert_eq!(global.total_entries, 2);
    }
}
