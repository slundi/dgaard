//! Runtime configuration tests for dgaard DNS proxy.
//!
//! Each test starts a real dgaard process with a targeted TOML configuration
//! and verifies that the behaviour changes as expected: RCODE, stats action,
//! and block reasons. Tests are deliberately narrow — each exercises one
//! configuration knob in isolation.
//!
//! Run with:  cargo nextest run --test config_test

use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Timing constants
// ---------------------------------------------------------------------------

const STARTUP_TIMEOUT: Duration = Duration::from_secs(8);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const STATS_READ_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_free_udp_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("cannot bind :0");
    sock.local_addr().unwrap().port()
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dgaard"))
}

// ---------------------------------------------------------------------------
// FlexServer — spawns dgaard with a template config
// ---------------------------------------------------------------------------

struct FlexServer {
    pub port: u16,
    pub socket_path: PathBuf,
    child: Child,
    _dir: TempDir,
}

impl FlexServer {
    /// Start dgaard with a TOML config that may contain `{port}` and
    /// `{socket}` tokens which are replaced with OS-allocated values.
    fn start(config_template: &str) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let port = find_free_udp_port();
        let socket_path = dir.path().join("stats.sock");

        let config = config_template
            .replace("{port}", &port.to_string())
            .replace("{socket}", &socket_path.to_string_lossy());

        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, config).expect("write config");

        let child = Command::new(binary())
            .arg("--config")
            .arg(&config_path)
            .spawn()
            .expect("spawn dgaard");

        let srv = Self {
            port,
            socket_path,
            child,
            _dir: dir,
        };
        srv.wait_ready();
        srv
    }

    fn wait_ready(&self) {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse().unwrap();
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if Instant::now() > deadline {
                panic!(
                    "dgaard on port {} did not respond within {:?}",
                    self.port, STARTUP_TIMEOUT
                );
            }
            if let Ok(sock) = UdpSocket::bind("127.0.0.1:0") {
                sock.set_read_timeout(Some(Duration::from_millis(300))).ok();
                let probe = build_dns_query(0xBEEF, "example.com", QTYPE_A, QCLASS_IN);
                if sock.send_to(&probe, addr).is_ok() {
                    let mut buf = [0u8; 512];
                    if sock.recv_from(&mut buf).is_ok() {
                        return;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn query(&self, domain: &str, qtype: u16) -> Vec<u8> {
        self.query_with_class(domain, qtype, QCLASS_IN)
    }

    fn query_with_class(&self, domain: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse().unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind client socket");
        sock.set_read_timeout(Some(QUERY_TIMEOUT))
            .expect("set timeout");

        let pkt = build_dns_query(0x1234, domain, qtype, qclass);
        sock.send_to(&pkt, addr).expect("send query");

        let mut buf = [0u8; 4096];
        let (len, _) = sock.recv_from(&mut buf).expect("recv response");
        buf[..len].to_vec()
    }

    fn connect_stats(&self) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match UnixStream::connect(&self.socket_path) {
                Ok(s) => {
                    s.set_read_timeout(Some(STATS_READ_TIMEOUT)).ok();
                    return s;
                }
                Err(_) => {
                    if Instant::now() > deadline {
                        panic!("could not connect to stats socket");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

impl Drop for FlexServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// DNS wire helpers
// ---------------------------------------------------------------------------

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;
const QCLASS_CHAOS: u16 = 3;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;

/// Build a minimal DNS query with explicit QTYPE and QCLASS.
fn build_dns_query(txid: u16, domain: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&txid.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    for label in domain.trim_end_matches('.').split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // root label
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&qclass.to_be_bytes());
    buf
}

fn rcode(resp: &[u8]) -> u8 {
    if resp.len() < 4 { 0 } else { resp[3] & 0x0F }
}

// ---------------------------------------------------------------------------
// Stats message deserialization (mirrors integration_test.rs wire format)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum StatAction {
    Allowed,
    Proxied,
    Blocked(u32),
    Suspicious(u32),
    HighlySuspicious(u32),
}

#[derive(Debug)]
#[allow(dead_code)]
enum StatMessage {
    DomainMapping { domain: String },
    Event { action: StatAction },
}

const REASON_STATIC_BLACKLIST: u32 = 1 << 0;
const REASON_BANNED_KEYWORD: u32 = 1 << 4;

fn drain_pending_messages(stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_millis(150)))
        .ok();
    while read_stat_message(stream).is_some() {}
    stream.set_read_timeout(Some(STATS_READ_TIMEOUT)).ok();
}

fn read_stat_message(stream: &mut UnixStream) -> Option<StatMessage> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).ok()?;
    let msg_len = u16::from_le_bytes(len_buf) as usize;

    let mut payload = vec![0u8; msg_len];
    stream.read_exact(&mut payload).ok()?;

    let msg_type = *payload.first()?;
    let data = &payload[1..];

    match msg_type {
        0x00 => {
            // DomainMapping: [hash:8][domain_len:2][domain:N]
            if data.len() < 10 {
                return None;
            }
            let dlen = u16::from_le_bytes(data[8..10].try_into().ok()?) as usize;
            if data.len() < 10 + dlen {
                return None;
            }
            let domain = String::from_utf8(data[10..10 + dlen].to_vec()).ok()?;
            Some(StatMessage::DomainMapping { domain })
        }
        0x01 => {
            // Event: [ts:8][hash:8][ip:16][action:1][reason?:4]
            if data.len() < 33 {
                return None;
            }
            let action_byte = data[32];
            let action = match action_byte {
                0 => StatAction::Allowed,
                1 => StatAction::Proxied,
                2..=4 => {
                    if data.len() < 37 {
                        return None;
                    }
                    let bits = u32::from_le_bytes(data[33..37].try_into().ok()?);
                    match action_byte {
                        2 => StatAction::Blocked(bits),
                        3 => StatAction::Suspicious(bits),
                        4 => StatAction::HighlySuspicious(bits),
                        _ => unreachable!(),
                    }
                }
                _ => return None,
            };
            Some(StatMessage::Event { action })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Base configuration template
// ---------------------------------------------------------------------------

/// Minimal safe baseline with all security checks at their defaults.
/// Tests substitute `{port}` and `{socket}` via `FlexServer::start`.
const BASE_CONFIG: &str = r#"
[server]
listen_addr = "127.0.0.1:{port}"
stats_socket_path = "{socket}"
block_idn = true
pipeline = ["Whitelist", "HotCache", "StaticBlock", "SuffixMatch", "Heuristics", "Upstream"]

[server.runtime]
worker_threads = 1

[upstream]
servers = ["1.1.1.1:53"]
timeout_ms = 3000

[security.structure]
max_subdomain_depth = 5
max_domain_length = 128
force_lowercase_ascii = true
block_chaos_class = true

[security.intelligence]
enabled = true
entropy_threshold = 4.0
min_word_length = 8
entropy_fast = true
consonant_ratio_threshold = 0.6
max_consonant_sequence = 5

[security.qtype_warden]
enabled = true
blocked_types = [10, 13, 255]

[security.lexical]
enabled = false
banned_keywords = []
strict_keyword_matching = true

[sources]
blacklists = []
whitelists = []
nrd_list_path = ""
browser_rules_path = ""
"#;

// ---------------------------------------------------------------------------
// Tests — structure and DNS class
// ---------------------------------------------------------------------------

#[test]
fn chaos_query_returns_refused() {
    let srv = FlexServer::start(BASE_CONFIG);
    // CHAOS class (qclass=3) is blocked before any domain processing.
    let resp = srv.query_with_class("example.com", QTYPE_A, QCLASS_CHAOS);
    assert_eq!(
        rcode(&resp),
        RCODE_REFUSED,
        "CHAOS class query must return REFUSED (RCODE=5) when block_chaos_class=true"
    );
}

#[test]
fn max_domain_length_blocks_long_domain() {
    // "averylongdomainname.com" is 23 chars — exceeds the configured limit of 20.
    let config = BASE_CONFIG.replace("max_domain_length = 128", "max_domain_length = 20");
    let srv = FlexServer::start(&config);
    let resp = srv.query("averylongdomainname.com", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "domain exceeding max_domain_length must return NXDOMAIN"
    );
}

#[test]
fn custom_subdomain_depth_blocks_slightly_deep_domain() {
    // "a.b.c.example.com" has 4 dots; default max is 5, custom limit is 2.
    let config = BASE_CONFIG.replace("max_subdomain_depth = 5", "max_subdomain_depth = 2");
    let srv = FlexServer::start(&config);
    let resp = srv.query("a.b.c.example.com", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "domain with 4 dots must be blocked when max_subdomain_depth=2"
    );
}

// ---------------------------------------------------------------------------
// Tests — lexical keyword filter
// ---------------------------------------------------------------------------

#[test]
fn lexical_banned_keyword_blocks_domain() {
    let config = BASE_CONFIG.replace(
        "[security.lexical]\nenabled = false\nbanned_keywords = []\nstrict_keyword_matching = true",
        "[security.lexical]\nenabled = true\nbanned_keywords = [\"badkeyword\"]\nstrict_keyword_matching = true",
    );
    let srv = FlexServer::start(&config);
    let mut stats = srv.connect_stats();
    drain_pending_messages(&mut stats);

    // "badkeyword" is a complete label in "badkeyword.example.com".
    let resp = srv.query("badkeyword.example.com", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "domain containing a banned keyword must be blocked"
    );

    // Verify the BANNED_KEYWORD reason appears in the stat event.
    let _mapping = read_stat_message(&mut stats).expect("expected DomainMapping");
    let event = read_stat_message(&mut stats).expect("expected Event");
    match event {
        StatMessage::Event {
            action: StatAction::Blocked(bits),
        } => {
            assert!(
                bits & REASON_BANNED_KEYWORD != 0,
                "keyword block must carry BANNED_KEYWORD reason, got bits: 0x{bits:08x}"
            );
        }
        other => panic!("expected Blocked event, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests — TLD filtering
// ---------------------------------------------------------------------------

#[test]
fn tld_exclude_blocks_matching_tld() {
    let config = format!("{BASE_CONFIG}\n[tld]\nexclude = [\".xyz\"]\n");
    let srv = FlexServer::start(&config);
    let resp = srv.query("example.xyz", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "domain with an excluded TLD must be blocked"
    );
}

// ---------------------------------------------------------------------------
// Tests — whitelist / blocklist interaction
// ---------------------------------------------------------------------------

#[test]
fn whitelist_overrides_blocklist() {
    // The files directory must outlive FlexServer (declared first, dropped last).
    let files_dir = TempDir::new().expect("files tempdir");
    let blacklist_path = files_dir.path().join("blacklist.txt");
    let whitelist_path = files_dir.path().join("whitelist.txt");
    std::fs::write(&blacklist_path, "allowed-domain.com\n").expect("write blacklist");
    std::fs::write(&whitelist_path, "allowed-domain.com\n").expect("write whitelist");

    let config = BASE_CONFIG
        .replace(
            "blacklists = []",
            &format!("blacklists = [\"{}\"]", blacklist_path.display()),
        )
        .replace(
            "whitelists = []",
            &format!("whitelists = [\"{}\"]", whitelist_path.display()),
        );

    let srv = FlexServer::start(&config);
    let mut stats = srv.connect_stats();
    drain_pending_messages(&mut stats);

    let _ = srv.query("allowed-domain.com", QTYPE_A);

    let _mapping = read_stat_message(&mut stats).expect("expected DomainMapping");
    let event = read_stat_message(&mut stats).expect("expected Event");
    match event {
        StatMessage::Event { action } => {
            assert!(
                !matches!(action, StatAction::Blocked(bits) if bits & REASON_STATIC_BLACKLIST != 0),
                "whitelisted domain must NOT be blocked by the static blacklist, got: {action:?}"
            );
        }
        other => panic!("expected Event, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests — intelligence / DGA heuristics
// ---------------------------------------------------------------------------

#[test]
fn intelligence_disabled_allows_high_entropy_domain() {
    // "a1b2c3d4e5f6g7h8i9j0" has entropy ≈ 4.32, above the default threshold 4.0.
    // With intelligence disabled entirely, the entropy check must not fire.
    let config = BASE_CONFIG.replace(
        "enabled = true\nentropy_threshold = 4.0",
        "enabled = false\nentropy_threshold = 4.0",
    );
    let srv = FlexServer::start(&config);
    let mut stats = srv.connect_stats();
    drain_pending_messages(&mut stats);

    let _ = srv.query("a1b2c3d4e5f6g7h8i9j0.com", QTYPE_A);

    let _mapping = read_stat_message(&mut stats).expect("expected DomainMapping");
    let event = read_stat_message(&mut stats).expect("expected Event");
    match event {
        StatMessage::Event { action } => {
            assert!(
                !matches!(&action, StatAction::Blocked(_)),
                "high-entropy domain must not be blocked when intelligence is disabled, got: {action:?}"
            );
        }
        other => panic!("expected Event, got: {other:?}"),
    }
}

#[test]
fn lower_entropy_threshold_blocks_moderate_entropy_domain() {
    // "abcde1234" has 9 unique chars → entropy = log2(9) ≈ 3.17.
    // With default threshold 4.0: 3.17 < 4.0 → NOT blocked.
    // With threshold 3.0: 3.17 > 3.0 → BLOCKED by entropy.
    // Consonant ratio = 3/5 = 0.60; raising threshold to 0.99 isolates the entropy test.
    let config = BASE_CONFIG
        .replace("entropy_threshold = 4.0", "entropy_threshold = 3.0")
        .replace(
            "consonant_ratio_threshold = 0.6",
            "consonant_ratio_threshold = 0.99",
        );
    let srv = FlexServer::start(&config);
    let resp = srv.query("abcde1234.com", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "domain with entropy ≈ 3.17 must be blocked when entropy_threshold=3.0"
    );
}

#[test]
fn consonant_clustering_config_blocks_domain() {
    // "engthsaaa" contains the consonant sequence "ngths" (5 consecutive consonants).
    // consonant ratio = 5/9 ≈ 0.56 < 0.6 → ratio check does not trigger.
    // With max_consonant_sequence = 5 (default): 5 is NOT > 5 → NOT blocked.
    // With max_consonant_sequence = 4: 5 > 4 → BLOCKED by clustering.
    let config = BASE_CONFIG.replace("max_consonant_sequence = 5", "max_consonant_sequence = 4");
    let srv = FlexServer::start(&config);
    let resp = srv.query("engthsaaa.com", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "domain with 5 consecutive consonants must be blocked when max_consonant_sequence=4"
    );
}

// ---------------------------------------------------------------------------
// Tests — QType Warden
// ---------------------------------------------------------------------------

#[test]
fn custom_qtype_aaaa_blocked_by_warden() {
    // Type 28 (AAAA) is not in the default blocked list; adding it blocks IPv6 queries.
    let config = BASE_CONFIG.replace(
        "blocked_types = [10, 13, 255]",
        "blocked_types = [10, 13, 28, 255]",
    );
    let srv = FlexServer::start(&config);
    let resp = srv.query("example.com", QTYPE_AAAA);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "AAAA query must be blocked when type 28 is added to blocked_types"
    );
}

// ---------------------------------------------------------------------------
// Tests — pipeline customisation
// ---------------------------------------------------------------------------

#[test]
fn pipeline_without_static_block_ignores_blocklist() {
    // "allowed-domain.com" has low entropy (≈ 3.24) and consonant ratio (0.54),
    // so no heuristic blocks it when StaticBlock is absent from the pipeline.
    //
    // Assertion is on the DNS RCODE rather than the stats stream so the test
    // does not depend on upstream DNS reachability: StaticBlock returns NXDOMAIN
    // (RCODE 3) when it fires; without it the query is proxied (NOERROR/0) or
    // the upstream fails (SERVFAIL/2) — either way, not NXDOMAIN.
    let files_dir = TempDir::new().expect("files tempdir");
    let blacklist_path = files_dir.path().join("blacklist.txt");
    std::fs::write(&blacklist_path, "allowed-domain.com\n").expect("write blacklist");

    let config = BASE_CONFIG
        .replace(
            r#"pipeline = ["Whitelist", "HotCache", "StaticBlock", "SuffixMatch", "Heuristics", "Upstream"]"#,
            r#"pipeline = ["Whitelist", "HotCache", "SuffixMatch", "Heuristics", "Upstream"]"#,
        )
        .replace(
            "blacklists = []",
            &format!("blacklists = [\"{}\"]", blacklist_path.display()),
        );

    let srv = FlexServer::start(&config);
    let resp = srv.query("allowed-domain.com", QTYPE_A);
    assert_ne!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "pipeline without StaticBlock must not return NXDOMAIN for a blocklisted domain"
    );
}
