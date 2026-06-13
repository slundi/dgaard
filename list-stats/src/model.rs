use std::collections::HashSet;

#[derive(Debug, Clone, serde::Serialize)]
pub struct FreqEntry {
    pub value: String,
    pub count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EntryTypes {
    pub plain: usize,
    pub wildcard: usize,
    pub regex: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ListStats {
    pub name: String,
    pub url: String,
    pub category: String,
    pub count: usize,
    pub entry_types: EntryTypes,
    pub top_tlds: Vec<FreqEntry>,
    pub top_words: Vec<FreqEntry>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CategoryStats {
    pub name: String,
    pub total: usize,
    pub unique: usize,
    pub lists: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OverlapEntry {
    pub list_a: String,
    pub list_b: String,
    pub shared: usize,
    pub pct_a: f32,
    pub pct_b: f32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GlobalStats {
    pub total_entries: usize,
    pub unique_entries: usize,
    pub top_tlds: Vec<FreqEntry>,
    pub top_words: Vec<FreqEntry>,
    pub entry_types: EntryTypes,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Report {
    pub generated_at: String,
    pub global: GlobalStats,
    pub lists: Vec<ListStats>,
    pub categories: Vec<CategoryStats>,
    pub overlap_matrix: Vec<OverlapEntry>,
}

/// Raw per-list data used internally before building the final Report.
pub struct ListData {
    pub name: String,
    pub url: String,
    pub category: String,
    /// xxh64 hashes of plain domain entries (used for overlap computation).
    pub domain_hashes: HashSet<u64>,
    /// Plain domain strings (used for TLD/word frequency analysis).
    pub domains: Vec<String>,
    /// Number of wildcard entries.
    pub wildcard_count: usize,
    /// Number of regex entries.
    pub regex_count: usize,
}
