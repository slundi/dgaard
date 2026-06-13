use std::{
    io::{BufWriter, Write as _},
    path::Path,
};

use crate::model::{ListData, Report};

/// Write the report as pretty-printed JSON to `path`.
/// This is the only place in the workspace that uses serde_json.
pub fn write_json(report: &Report, path: &Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(report)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// Write all plain domain entries as CSV to `path`.
/// Columns: domain,tld,depth,category,list_name
pub fn write_csv(all_data: &[ListData], path: &Path) -> std::io::Result<()> {
    let file = std::fs::File::create(path)?;
    let mut w = BufWriter::new(file);
    writeln!(w, "domain,tld,depth,category,list_name")?;
    for data in all_data {
        for domain in &data.domains {
            let tld = domain.rfind('.').map(|i| &domain[i..]).unwrap_or(domain);
            let depth = dgaard_engine::utils::count_dots(domain);
            let category = csv_escape(&data.category);
            let list_name = csv_escape(&data.name);
            let domain_esc = csv_escape(domain);
            writeln!(w, "{domain_esc},{tld},{depth},{category},{list_name}")?;
        }
    }
    w.flush()
}

/// Wrap a CSV field in double quotes if it contains a comma, quote, or newline.
fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use std::collections::HashSet;
    use tempfile::NamedTempFile;

    fn minimal_report() -> Report {
        Report {
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            global: GlobalStats {
                total_entries: 0,
                unique_entries: 0,
                top_tlds: vec![],
                top_words: vec![],
                entry_types: EntryTypes {
                    plain: 0,
                    wildcard: 0,
                    regex: 0,
                },
            },
            lists: vec![],
            categories: vec![],
            overlap_matrix: vec![],
        }
    }

    #[test]
    fn test_write_json_round_trip() {
        let report = minimal_report();
        let f = NamedTempFile::new().unwrap();
        write_json(&report, f.path()).unwrap();
        let content = std::fs::read_to_string(f.path()).unwrap();
        assert!(content.contains("generated_at"));
        assert!(content.contains("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn test_write_csv_header() {
        let data = vec![ListData {
            name: "test-list".to_string(),
            url: "https://example.com".to_string(),
            category: "ads".to_string(),
            domain_hashes: HashSet::new(),
            domains: vec!["ads.example.com".to_string(), "tracker.net".to_string()],
            wildcard_count: 0,
            regex_count: 0,
        }];
        let f = NamedTempFile::new().unwrap();
        write_csv(&data, f.path()).unwrap();
        let content = std::fs::read_to_string(f.path()).unwrap();
        let first_line = content.lines().next().unwrap();
        assert_eq!(first_line, "domain,tld,depth,category,list_name");
    }

    #[test]
    fn test_write_csv_rows() {
        let data = vec![ListData {
            name: "test-list".to_string(),
            url: "https://example.com".to_string(),
            category: "ads".to_string(),
            domain_hashes: HashSet::new(),
            domains: vec!["ads.example.com".to_string()],
            wildcard_count: 0,
            regex_count: 0,
        }];
        let f = NamedTempFile::new().unwrap();
        write_csv(&data, f.path()).unwrap();
        let content = std::fs::read_to_string(f.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "header + 1 data row");
        assert!(lines[1].contains("ads.example.com"));
        assert!(lines[1].contains(".com"));
        assert!(lines[1].contains("ads"));
        assert!(lines[1].contains("test-list"));
    }
}
