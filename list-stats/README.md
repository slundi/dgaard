# list-stats

A standalone Rust binary that analyses DNS blocklists and produces:

- A JSON file with per-list, per-category and global statistics
- A CSV file (one row per domain entry) for ad-hoc analysis
- A static HTML page (ECharts) that reads the JSON file

## Statistics computed

**Per list**

- Entry count (total, plain domains, wildcards, regexes)
- Top TLDs (last DNS label, e.g. `.com`)
- Tokenized word frequencies (split on `.` `-` `_`, skip single chars and TLD tokens)

**Global**

- Total entries, unique entries across all lists
- Top TLDs and top words aggregated
- Entry type breakdown (plain / wildcard / regex)

**Per category** (ads, privacy, malware, gambling, porn, fake-news, annoyances)

- Same as per-list, rolled up by category

**Overlap matrix**

- For every pair of lists: shared entry count and percentage relative to each list
- Useful for choosing a minimal non-redundant list set

## Built-in sources

| Name                 | URL                                                 | Category   |
| -------------------- | --------------------------------------------------- | ---------- |
| uBlock-ads           | uBlockOrigin/uAssets filters/filters.txt            | ads        |
| uBlock-privacy       | uBlockOrigin/uAssets filters/privacy.txt            | privacy    |
| uBlock-malware       | uBlockOrigin/uAssets filters/badware.txt            | malware    |
| uBlock-cookies       | uBlockOrigin/uAssets filters/annoyances-cookies.txt | annoyances |
| StevenBlack          | StevenBlack/hosts hosts                             | ads        |
| StevenBlack-fakenews | StevenBlack/hosts alternates/fakenews/hosts         | fake-news  |
| StevenBlack-gambling | StevenBlack/hosts alternates/gambling/hosts         | gambling   |
| StevenBlack-porn     | StevenBlack/hosts alternates/porn/hosts             | porn       |
| oisd-big             | big.oisd.nl/domainswild                             | ads        |

## Output JSON structure

```json
{
  "generated_at": "ISO-8601 timestamp",
  "global": {
    "total_entries": 0,
    "unique_entries": 0,
    "top_tlds": [{ "tld": ".com", "count": 0 }],
    "top_words": [{ "word": "ads", "count": 0 }],
    "entry_types": { "plain": 0, "wildcard": 0, "regex": 0 }
  },
  "lists": [{
    "name": "uBlock-ads",
    "url": "...",
    "category": "ads",
    "count": 0,
    "entry_types": { "plain": 0, "wildcard": 0, "regex": 0 },
    "top_tlds": [],
    "top_words": []
  }],
  "categories": [{ "name": "ads", "total": 0, "lists": [] }],
  "overlap_matrix": [{
    "list_a": "uBlock-ads",
    "list_b": "oisd-big",
    "shared": 0,
    "pct_a": 0.0,
    "pct_b": 0.0
  }]
}
```

## Usage

```
list-stats [--output-dir <dir>] [--top <n>]
```

Options:

- `--output-dir` Path for output files (default: `./output`)
- `--top` Number of top TLDs/words to keep per list (default: 20)
