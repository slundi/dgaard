use std::collections::HashSet;

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
