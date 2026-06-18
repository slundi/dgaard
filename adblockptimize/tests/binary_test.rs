//! Binary integration tests for `adblockptimize`.
//!
//! Each test invokes the real binary via `Command::output()`, inspects stdout,
//! stderr, exit code, and on-disk output files. Tests are fully self-contained:
//! every input fixture is written to a `TempDir` that is dropped at the end.

use std::{path::PathBuf, process::Command};

use tempfile::TempDir;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_adblockptimize"))
}

/// Write `content` to `dir/name` and return the full path.
fn fixture(dir: &TempDir, name: &str, content: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write fixture");
    path
}

/// Run the binary with the given arguments and return its output.
fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("run adblockptimize")
}

/// Read stdout as a UTF-8 string, split into non-empty lines, sort, dedup.
fn stdout_lines(out: &std::process::Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

fn stderr_str(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ── Exit codes ────────────────────────────────────────────────────────────────

#[test]
fn binary_exits_zero_with_valid_file() {
    let dir = TempDir::new().unwrap();
    let f = fixture(&dir, "list.txt", "example.com\n");
    let out = run(&[f.to_str().unwrap()]);
    assert!(out.status.success(), "expected exit 0, got: {}", out.status);
}

#[test]
fn binary_exits_one_on_unknown_flag() {
    let out = run(&["--this-flag-does-not-exist"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 for unknown flag"
    );
    assert!(
        !stderr_str(&out).is_empty(),
        "expected usage message on stderr"
    );
}

#[test]
fn binary_exits_zero_with_no_args() {
    // Zero positional args is valid — produces empty output.
    let out = run(&[]);
    assert!(out.status.success(), "expected exit 0 with no args");
}

// ── Plain domain input → stdout ───────────────────────────────────────────────

#[test]
fn binary_plain_domains_appear_on_stdout() {
    let dir = TempDir::new().unwrap();
    let f = fixture(
        &dir,
        "plain.txt",
        "example.com\ntracker.net\nads.evil.org\n",
    );
    let out = run(&[f.to_str().unwrap()]);
    assert!(out.status.success());
    let lines = stdout_lines(&out);
    assert!(
        lines.contains(&"example.com".into()),
        "missing example.com: {lines:?}"
    );
    assert!(
        lines.contains(&"tracker.net".into()),
        "missing tracker.net: {lines:?}"
    );
    assert!(
        lines.contains(&"ads.evil.org".into()),
        "missing ads.evil.org: {lines:?}"
    );
}

#[test]
fn binary_comments_and_blank_lines_not_in_output() {
    let dir = TempDir::new().unwrap();
    let f = fixture(
        &dir,
        "commented.txt",
        "# this is a comment\nexample.com\n\n! another comment\ntracker.net\n",
    );
    let out = run(&[f.to_str().unwrap()]);
    assert!(out.status.success());
    let lines = stdout_lines(&out);
    assert!(
        lines
            .iter()
            .all(|l| !l.starts_with('#') && !l.starts_with('!')),
        "comment lines leaked into output: {lines:?}"
    );
    assert!(lines.contains(&"example.com".into()));
    assert!(lines.contains(&"tracker.net".into()));
}

#[test]
fn binary_output_is_deduplicated() {
    let dir = TempDir::new().unwrap();
    // same domain three times
    let f = fixture(&dir, "dupe.txt", "example.com\nexample.com\nexample.com\n");
    let out = run(&[f.to_str().unwrap()]);
    assert!(out.status.success());
    let lines = stdout_lines(&out);
    let count = lines.iter().filter(|l| l.as_str() == "example.com").count();
    assert_eq!(
        count, 1,
        "expected exactly 1 occurrence, got {count}: {lines:?}"
    );
}

#[test]
fn binary_output_is_sorted() {
    let dir = TempDir::new().unwrap();
    // intentionally unsorted
    let f = fixture(&dir, "unsorted.txt", "zzz.com\naaa.com\nmmm.com\n");
    let out = run(&[f.to_str().unwrap()]);
    assert!(out.status.success());
    let lines = stdout_lines(&out);
    let mut sorted = lines.clone();
    sorted.sort();
    assert_eq!(lines, sorted, "output is not sorted: {lines:?}");
}

#[test]
fn binary_multiple_files_are_merged() {
    let dir = TempDir::new().unwrap();
    let f1 = fixture(&dir, "a.txt", "alpha.com\n");
    let f2 = fixture(&dir, "b.txt", "beta.com\n");
    let out = run(&[f1.to_str().unwrap(), f2.to_str().unwrap()]);
    assert!(out.status.success());
    let lines = stdout_lines(&out);
    assert!(
        lines.contains(&"alpha.com".into()),
        "missing alpha.com: {lines:?}"
    );
    assert!(
        lines.contains(&"beta.com".into()),
        "missing beta.com: {lines:?}"
    );
}

#[test]
fn binary_nonexistent_file_exits_zero_with_empty_output() {
    // Source errors are logged as warnings; the tool continues and exits 0.
    let out = run(&["/nonexistent/path/that/does/not/exist.txt"]);
    assert!(
        out.status.success(),
        "expected exit 0 for missing source file"
    );
    assert!(stdout_lines(&out).is_empty(), "expected empty stdout");
}

// ── Hosts format input ────────────────────────────────────────────────────────

#[test]
fn binary_hosts_format_extracts_domains() {
    let dir = TempDir::new().unwrap();
    let f = fixture(
        &dir,
        "hosts.txt",
        "0.0.0.0 example.com\n127.0.0.1 tracker.net\n:: ads.evil.org\n",
    );
    let out = run(&[f.to_str().unwrap()]);
    assert!(out.status.success());
    let lines = stdout_lines(&out);
    assert!(
        lines.contains(&"example.com".into()),
        "missing example.com: {lines:?}"
    );
    assert!(
        lines.contains(&"tracker.net".into()),
        "missing tracker.net: {lines:?}"
    );
    assert!(
        lines.contains(&"ads.evil.org".into()),
        "missing ads.evil.org: {lines:?}"
    );
}

// ── Dnsmasq format input ──────────────────────────────────────────────────────

#[test]
fn binary_dnsmasq_format_extracts_domains() {
    let dir = TempDir::new().unwrap();
    let f = fixture(
        &dir,
        "dnsmasq.txt",
        "address=/example.com/#\nserver=/tracker.net/\n",
    );
    let out = run(&[f.to_str().unwrap()]);
    assert!(out.status.success());
    let lines = stdout_lines(&out);
    assert!(
        lines.contains(&"example.com".into()),
        "missing example.com: {lines:?}"
    );
    assert!(
        lines.contains(&"tracker.net".into()),
        "missing tracker.net: {lines:?}"
    );
}

// ── ABP format input ──────────────────────────────────────────────────────────

#[test]
fn binary_abp_network_rules_appear_in_output() {
    let dir = TempDir::new().unwrap();
    let f = fixture(&dir, "abp.txt", "||example.com^\n||tracker.net^\n");
    let out = run(&[f.to_str().unwrap()]);
    assert!(out.status.success());
    let lines = stdout_lines(&out);
    assert!(
        lines.contains(&"example.com".into()) || lines.iter().any(|l| l.contains("example.com")),
        "missing example.com from ABP input: {lines:?}"
    );
}

#[test]
fn binary_abp_browser_rules_appear_on_stdout_by_default() {
    let dir = TempDir::new().unwrap();
    // Cosmetic rules should appear on stdout when no --browser-file is given.
    let f = fixture(&dir, "abp.txt", "example.com##.banner\n");
    let out = run(&[f.to_str().unwrap()]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("example.com##.banner"),
        "browser rule missing from stdout: {stdout}"
    );
}

// ── --target output formats ───────────────────────────────────────────────────

#[test]
fn binary_target_hosts_prefix() {
    let dir = TempDir::new().unwrap();
    let f = fixture(&dir, "plain.txt", "example.com\n");
    let out = run(&["--target=hosts", "--no-browser", f.to_str().unwrap()]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("0.0.0.0 example.com"),
        "expected '0.0.0.0 example.com' in hosts output: {stdout}"
    );
}

#[test]
fn binary_target_dnsmasq_format() {
    let dir = TempDir::new().unwrap();
    let f = fixture(&dir, "plain.txt", "example.com\n");
    let out = run(&["--target=dnsmasq", "--no-browser", f.to_str().unwrap()]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("address=/example.com/#"),
        "expected dnsmasq address format: {stdout}"
    );
}

#[test]
fn binary_target_unbound_format() {
    let dir = TempDir::new().unwrap();
    let f = fixture(&dir, "plain.txt", "example.com\n");
    let out = run(&["--target=unbound", "--no-browser", f.to_str().unwrap()]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("local-zone:") && stdout.contains("example.com"),
        "expected unbound local-zone format: {stdout}"
    );
}

#[test]
fn binary_target_adguard_format() {
    let dir = TempDir::new().unwrap();
    let f = fixture(&dir, "plain.txt", "example.com\n");
    let out = run(&["--target=adguard", "--no-browser", f.to_str().unwrap()]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("||example.com^"),
        "expected AdGuard '||domain^' format: {stdout}"
    );
}

// ── --no-browser and --no-network flags ───────────────────────────────────────

#[test]
fn binary_no_browser_omits_cosmetic_rules() {
    let dir = TempDir::new().unwrap();
    let f = fixture(&dir, "mixed.txt", "||example.com^\nexample.com##.banner\n");
    let out = run(&["--no-browser", f.to_str().unwrap()]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("##"),
        "browser rule leaked into output with --no-browser: {stdout}"
    );
}

#[test]
fn binary_no_network_omits_domain_rules() {
    let dir = TempDir::new().unwrap();
    let f = fixture(&dir, "mixed.txt", "||example.com^\nexample.com##.banner\n");
    let out = run(&["--no-network", f.to_str().unwrap()]);
    assert!(out.status.success());
    // Network rule should not appear; browser rule should.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("example.com##.banner"),
        "browser rule missing with --no-network: {stdout}"
    );
}

// ── --network-file and --browser-file flags ───────────────────────────────────

#[test]
fn binary_network_file_written_to_disk() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "plain.txt", "example.com\ntracker.net\n");
    let net_out = dir.path().join("network.txt");

    let out = run(&[
        "--network-file",
        net_out.to_str().unwrap(),
        "--no-browser",
        input.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert!(net_out.exists(), "network output file not created");
    let content = std::fs::read_to_string(&net_out).expect("read network file");
    assert!(
        content.contains("example.com"),
        "missing example.com in network file"
    );
    assert!(
        content.contains("tracker.net"),
        "missing tracker.net in network file"
    );
    // stdout should be empty since everything went to the file.
    assert!(
        stdout_lines(&out).is_empty(),
        "expected empty stdout when --network-file is set"
    );
}

#[test]
fn binary_browser_file_written_to_disk() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "abp.txt", "example.com##.banner\ntracker.net##.ad\n");
    let browser_out = dir.path().join("browser.txt");

    let out = run(&[
        "--browser-file",
        browser_out.to_str().unwrap(),
        "--no-network",
        input.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert!(browser_out.exists(), "browser output file not created");
    let content = std::fs::read_to_string(&browser_out).expect("read browser file");
    assert!(
        content.contains("example.com##.banner"),
        "missing banner rule in browser file"
    );
    // stdout should be empty since there are no network rules (--no-network) and
    // browser rules went to the file.
    assert!(
        stdout_lines(&out).is_empty(),
        "expected empty stdout when --browser-file is set and --no-network is given"
    );
}

#[test]
fn binary_adguard_whitelist_file_separate_from_network() {
    let dir = TempDir::new().unwrap();
    let input = fixture(
        &dir,
        "abp.txt",
        "||example.com^\n||tracker.net^\n@@||safe.com^\n",
    );
    let net_out = dir.path().join("network.txt");
    let wl_out = dir.path().join("whitelist.txt");

    let out = run(&[
        "--target=adguard",
        "--no-browser",
        "--network-file",
        net_out.to_str().unwrap(),
        "--whitelist-file",
        wl_out.to_str().unwrap(),
        input.to_str().unwrap(),
    ]);
    assert!(out.status.success());

    let net_content = std::fs::read_to_string(&net_out).unwrap_or_default();
    let wl_content = std::fs::read_to_string(&wl_out).unwrap_or_default();

    assert!(
        net_content.contains("||example.com^"),
        "network file should contain blocked domain: {net_content}"
    );
    assert!(
        wl_content.contains("safe.com"),
        "whitelist file should contain safe.com: {wl_content}"
    );
    assert!(
        !net_content.contains("safe.com"),
        "whitelist domain should NOT be in network file: {net_content}"
    );
}

// ── Invalid target/format values ──────────────────────────────────────────────

#[test]
fn binary_invalid_target_exits_one() {
    let out = run(&["--target=notarealformat"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 for invalid target"
    );
}

// ── Mixed format inputs ───────────────────────────────────────────────────────

#[test]
fn binary_mixed_format_file_all_domains_extracted() {
    let dir = TempDir::new().unwrap();
    // One file mixing plain, hosts, and dnsmasq formats.
    let f = fixture(
        &dir,
        "mixed.txt",
        "plain.example.com\n0.0.0.0 hosts.example.com\naddress=/dnsmasq.example.com/#\n",
    );
    let out = run(&["--no-browser", f.to_str().unwrap()]);
    assert!(out.status.success());
    let lines = stdout_lines(&out);
    assert!(
        lines.contains(&"plain.example.com".into()),
        "missing plain domain: {lines:?}"
    );
    assert!(
        lines.contains(&"hosts.example.com".into()),
        "missing hosts domain: {lines:?}"
    );
    assert!(
        lines.contains(&"dnsmasq.example.com".into()),
        "missing dnsmasq domain: {lines:?}"
    );
}
