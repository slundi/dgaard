# 🛡️ Parental Control: Smart Keyword Filtering

Dgaard includes a lightweight, high-performance "Smart Keyword" engine. Unlike traditional filters that require massive databases, this feature allows you to block entire categories of content (Adult, Gambling, Drugs) using just a few dozen strategic words.

## 1. The Principle: Label-Aware Matching

Traditional "wildcard" filters are often too aggressive (the *Scunthorpe Problem*), blocking legitimate sites because a forbidden word is hidden inside a longer, innocent word.

Dgaard uses **Label-Aware** Matching. A keyword only triggers a block if:

1. It is a complete label (e.g., `casino.com`).
2. It is separated by a hyphen (e.g., `play-casino.net`).
3. It matches a specific TLD known for malicious or low-quality content.

This ensures that `casino.com` is blocked, but `casinon-les-bains.fr` (a physical location) remain accessible.

## 2. TOML Configuration

Add the following section to your `dgaard.toml` to activate the engine.

```toml
[security.parental_control]
enabled = true

# High-risk keywords to monitor
keywords = ["porno", "casino", "bet", "drogue", "sex", "gambling"]

# If true, matches only if the keyword is a full label (more accurate)
# If false, matches if the keyword is found anywhere (more aggressive)
strict_matching = true

[tld]
# Combined Filter: Block if domain contains a [keyword] AND uses one of these TLDs
# This is a powerful "Grey-Zone" filter for .com or .net
suspicious_tlds = [".com", ".net", ".org", ".biz"]
```

## 3. Comparison with Other Systems

| Feature | Dgaard (Smart Keywords) | Pi-hole / AdGuard Home |
|:--------|:------------------------|:-----------------------|
| **RAM Usage** | **Ultra Low** (~KBs). Uses `Aho-Corasick` automaton. | **High** (MBs). Requires loading millions of domains. |
| **Proactivity** | **Instant**. Blocks new domains the second they are registered. | **Reactive**. Must wait for the domain to be added to a list. |
| **Maintenance** | **Set & Forget**. 10 keywords cover millions of sites. | **Constant**. Requires daily list updates. |
| **False Positives** | **Low**. Thanks to Label-Aware logic. | **Low**. But only for known sites. |
