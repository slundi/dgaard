//! Integration tests for dgaard DNS proxy.
//!
//! Each test spins up a real dgaard process on an ephemeral UDP port, sends
//! DNS queries, and asserts on both the DNS response and the binary stats
//! stream emitted over a Unix socket.
//!
//! Run with:  cargo nextest run --test integration_test

use std::fs;
use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Timing constants
// ---------------------------------------------------------------------------

const STARTUP_TIMEOUT: Duration = Duration::from_secs(8);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const STATS_READ_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Port / path allocation (unique across parallel tests in same process)
// ---------------------------------------------------------------------------

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn next_test_id() -> u32 {
    TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn find_free_udp_port() -> u16 {
    // Bind to :0 to get an OS-assigned ephemeral port, then release it.
    // dgaard will bind to the same port moments later.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("cannot bind to :0");
    sock.local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------
// Temp directory (cleaned up on drop)
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(id: u32) -> Self {
        let path = std::env::temp_dir().join(format!("dgaard_it_{}_{}", std::process::id(), id));
        fs::create_dir_all(&path).expect("failed to create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// TestServer — wraps a spawned dgaard child process
// ---------------------------------------------------------------------------

struct TestServer {
    pub port: u16,
    pub socket_path: PathBuf,
    child: Child,
    _dir: TempDir,
}

impl TestServer {
    /// Start dgaard with a plain-domain blocklist file from `tests/`.
    fn start(blocklist_filename: &str) -> Self {
        Self::build(blocklist_filename, true)
    }

    /// Like [`start`] but with `force_lowercase_ascii = false`.
    ///
    /// Required to reach the IDN check: when `force_lowercase_ascii` is true,
    /// non-ASCII domains (including decoded punycode) are caught by the
    /// structure check before the IDN check ever runs.
    fn start_with_idn_check(blocklist_filename: &str) -> Self {
        Self::build(blocklist_filename, false)
    }

    fn build(blocklist_filename: &str, force_lowercase_ascii: bool) -> Self {
        let id = next_test_id();
        let dir = TempDir::new(id);
        let port = find_free_udp_port();

        let socket_path = dir.path().join("stats.sock");
        let config_path = dir.path().join("config.toml");

        // Absolute path to the fixture blocklist in tests/
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let blocklist_path = PathBuf::from(manifest_dir)
            .join("tests")
            .join(blocklist_filename);

        let config = format!(
            r#"
[server]
listen_addr = "127.0.0.1:{port}"
stats_socket_path = "{socket}"
block_idn = true

[server.runtime]
worker_threads = 1

[upstream]
servers = ["1.1.1.1:53"]
timeout_ms = 3000

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

[security.structure]
max_subdomain_depth = 5
max_domain_length = 128
force_lowercase_ascii = {force_ascii}

[sources]
blacklists = ["{blocklist}"]
"#,
            port = port,
            socket = socket_path.display(),
            force_ascii = force_lowercase_ascii,
            blocklist = blocklist_path.display(),
        );

        fs::write(&config_path, &config).expect("failed to write config");

        let binary = env!("CARGO_BIN_EXE_dgaard");
        let child = Command::new(binary)
            .arg("--config")
            .arg(&config_path)
            .spawn()
            .expect("failed to spawn dgaard");

        let server = Self {
            port,
            socket_path,
            child,
            _dir: dir,
        };

        server.wait_ready();
        server
    }

    /// Poll until dgaard replies to a probe query or the timeout expires.
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
                let probe = build_dns_query(0xBEEF, "example.com", QTYPE_A);
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

    /// Send a DNS query and return the raw response bytes.
    fn query(&self, domain: &str, qtype: u16) -> Vec<u8> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse().unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind client socket");
        sock.set_read_timeout(Some(QUERY_TIMEOUT))
            .expect("set read timeout");

        let pkt = build_dns_query(0x1234, domain, qtype);
        sock.send_to(&pkt, addr).expect("send query");

        let mut buf = [0u8; 4096];
        let (len, _) = sock.recv_from(&mut buf).expect("recv response");
        buf[..len].to_vec()
    }

    /// Connect to the Unix stats socket and return the stream.
    /// Retries until the socket file appears or the deadline passes.
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

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// DNS packet helpers
// ---------------------------------------------------------------------------

const QTYPE_A: u16 = 1;
const QTYPE_ANY: u16 = 255;
const RCODE_NXDOMAIN: u8 = 3;

/// Build a minimal DNS query packet.
fn build_dns_query(txid: u16, domain: &str, qtype: u16) -> Vec<u8> {
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
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    buf
}

/// Extract the 4-bit RCODE from a DNS response.
fn rcode(resp: &[u8]) -> u8 {
    if resp.len() < 4 { 0 } else { resp[3] & 0x0F }
}

// ---------------------------------------------------------------------------
// Stats message deserialization
// (mirrors the binary wire format in dgaard/src/model/mod.rs)
// ---------------------------------------------------------------------------

/// Compact stat action for test assertions.
#[derive(Debug, PartialEq)]
enum StatAction {
    Allowed,
    Proxied,
    Blocked(u32), // StatBlockReason bitflags
    Suspicious(u32),
    HighlySuspicious(u32),
}

#[derive(Debug)]
enum StatMessage {
    DomainMapping {
        hash: u64,
        domain: String,
    },
    Event {
        domain_hash: u64,
        action: StatAction,
    },
}

// StatBlockReason bit positions (from dgaard/src/model/action.rs)
const REASON_STATIC_BLACKLIST: u32 = 1 << 0;
const REASON_HIGH_ENTROPY: u32 = 1 << 2;
const REASON_SUSPICIOUS_IDN: u32 = 1 << 6;
const REASON_FORBIDDEN_QTYPE: u32 = 1 << 11;

/// Drain any messages already buffered on the stream (server-side catchup on connect).
///
/// When a client connects to the stats socket the server immediately sends all
/// domain mappings it has seen so far. Tests that call `connect_stats()` after
/// `wait_ready()` would otherwise receive a stale `DomainMapping { "example.com" }`
/// from the readiness probe before the messages produced by the test query.
fn drain_pending_messages(stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_millis(150)))
        .ok();
    while read_stat_message(stream).is_some() {}
    stream.set_read_timeout(Some(STATS_READ_TIMEOUT)).ok();
}

/// Read one length-prefixed [`StatMessage`] from the stats socket stream.
///
/// Wire format:
/// ```text
/// [msg_len: u16 LE][type: u8][payload...]
///
/// DomainMapping (0x00): [hash: u64 LE][domain_len: u16 LE][domain: UTF-8]
/// Event         (0x01): [ts: u64 LE][hash: u64 LE][ip: 16][action: u8][reason?: u32 LE]
/// ```
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
            let hash = u64::from_le_bytes(data[0..8].try_into().ok()?);
            let dlen = u16::from_le_bytes(data[8..10].try_into().ok()?) as usize;
            if data.len() < 10 + dlen {
                return None;
            }
            let domain = String::from_utf8(data[10..10 + dlen].to_vec()).ok()?;
            Some(StatMessage::DomainMapping { hash, domain })
        }
        0x01 => {
            // Event: [ts:8][hash:8][ip:16][action:1][reason?:4]
            if data.len() < 33 {
                return None;
            }
            let domain_hash = u64::from_le_bytes(data[8..16].try_into().ok()?);
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
            Some(StatMessage::Event {
                domain_hash,
                action,
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// DNS response behaviour tests
// ---------------------------------------------------------------------------

#[test]
fn blocked_domain_returns_nxdomain() {
    let srv = TestServer::start("list_domain.txt");
    let resp = srv.query("samsungads.com", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "static-blocked domain must return NXDOMAIN"
    );
}

#[test]
fn non_blocked_domain_does_not_return_nxdomain() {
    let srv = TestServer::start("list_domain.txt");
    // "example.com" is not in the blocklist and has low entropy
    let resp = srv.query("example.com", QTYPE_A);
    assert_ne!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "non-blocked domain must not return NXDOMAIN"
    );
}

#[test]
fn multiple_blocked_domains_all_return_nxdomain() {
    let srv = TestServer::start("list_domain.txt");
    for domain in &["samsungads.com", "smartclip.net", "yumenetworks.com"] {
        let resp = srv.query(domain, QTYPE_A);
        assert_eq!(
            rcode(&resp),
            RCODE_NXDOMAIN,
            "domain {domain} should be blocked"
        );
    }
}

#[test]
fn idn_punycode_domain_blocked_when_block_idn_enabled() {
    // "xn--pple-43d.com" is a fake apple with Cyrillic а — confirmed by unit test
    let srv = TestServer::start("list_domain.txt");
    let resp = srv.query("xn--pple-43d.com", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "IDN/Punycode domain must be blocked"
    );
}

#[test]
fn deep_subdomain_blocked_by_structure_check() {
    // 7 dots > max_subdomain_depth=5 → InvalidStructure → immediate Block
    let srv = TestServer::start("list_domain.txt");
    let resp = srv.query("a.b.c.d.e.f.evil.example", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "domain exceeding max_subdomain_depth must be blocked"
    );
}

#[test]
fn high_entropy_dga_domain_blocked_by_heuristics() {
    // SLD "a1b2c3d4e5f6g7h8i9j0" — entropy ≈ 4.32 > threshold 4.0
    // Verified by the unit test test_is_dga_suspicious_high_entropy
    let srv = TestServer::start("list_domain.txt");
    let resp = srv.query("a1b2c3d4e5f6g7h8i9j0.com", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "high-entropy DGA domain must be blocked"
    );
}

#[test]
fn forbidden_qtype_any_returns_nxdomain() {
    // DNS ANY query (type 255) is blocked by the QType Warden
    let srv = TestServer::start("list_domain.txt");
    let resp = srv.query("example.com", QTYPE_ANY);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "ANY query must be blocked by QType Warden"
    );
}

#[test]
fn hosts_format_blocklist_blocks_domain() {
    let srv = TestServer::start("list_host.txt");
    let resp = srv.query("samsungads.com", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "hosts-format blocklist must block the domain"
    );
}

#[test]
fn abp_format_blocklist_blocks_domain() {
    let srv = TestServer::start("list_abp.txt");
    let resp = srv.query("samsungads.com", QTYPE_A);
    assert_eq!(
        rcode(&resp),
        RCODE_NXDOMAIN,
        "ABP-format blocklist must block the domain"
    );
}

// ---------------------------------------------------------------------------
// Stats socket tests
// ---------------------------------------------------------------------------

#[test]
fn first_query_sends_domain_mapping_then_event() {
    let srv = TestServer::start("list_domain.txt");
    let mut stats = srv.connect_stats();
    // Drain any catchup mappings replayed from before this client connected
    drain_pending_messages(&mut stats);

    let _ = srv.query("samsungads.com", QTYPE_A);

    let msg1 = read_stat_message(&mut stats).expect("expected DomainMapping");
    assert!(
        matches!(&msg1, StatMessage::DomainMapping { domain, .. } if domain == "samsungads.com"),
        "first message must be DomainMapping for the queried domain, got: {msg1:?}"
    );

    let msg2 = read_stat_message(&mut stats).expect("expected Event");
    assert!(
        matches!(&msg2, StatMessage::Event { .. }),
        "second message must be an Event, got: {msg2:?}"
    );
}

#[test]
fn second_query_same_domain_omits_domain_mapping() {
    let srv = TestServer::start("list_domain.txt");
    let mut stats = srv.connect_stats();
    drain_pending_messages(&mut stats);

    // First query: expect DomainMapping + Event
    let _ = srv.query("samsungads.com", QTYPE_A);
    let _mapping = read_stat_message(&mut stats).expect("expected DomainMapping");
    let _event1 = read_stat_message(&mut stats).expect("expected first Event");

    // Second query for the same domain: only Event, no DomainMapping
    let _ = srv.query("samsungads.com", QTYPE_A);
    let msg = read_stat_message(&mut stats).expect("expected second Event");
    assert!(
        matches!(&msg, StatMessage::Event { .. }),
        "second query must produce only an Event (no DomainMapping), got: {msg:?}"
    );
}

#[test]
fn different_domains_each_receive_own_domain_mapping() {
    let srv = TestServer::start("list_domain.txt");
    let mut stats = srv.connect_stats();
    drain_pending_messages(&mut stats);

    let _ = srv.query("samsungads.com", QTYPE_A);
    let _ = srv.query("smartclip.net", QTYPE_A);

    // Collect 4 messages: 2 DomainMappings + 2 Events (order may interleave)
    let mut mappings: Vec<String> = Vec::new();
    let mut event_count = 0usize;

    for _ in 0..4 {
        match read_stat_message(&mut stats).expect("expected stat message") {
            StatMessage::DomainMapping { domain, .. } => mappings.push(domain),
            StatMessage::Event { .. } => event_count += 1,
        }
    }

    assert_eq!(
        mappings.len(),
        2,
        "each unique domain must produce a DomainMapping"
    );
    assert_eq!(event_count, 2, "each query must produce an Event");
    assert!(mappings.contains(&"samsungads.com".to_string()));
    assert!(mappings.contains(&"smartclip.net".to_string()));
}

#[test]
fn blocked_domain_stats_carries_static_blacklist_reason() {
    let srv = TestServer::start("list_domain.txt");
    let mut stats = srv.connect_stats();
    drain_pending_messages(&mut stats);

    let _ = srv.query("samsungads.com", QTYPE_A);

    let _mapping = read_stat_message(&mut stats).expect("expected DomainMapping");
    let event = read_stat_message(&mut stats).expect("expected Event");

    match event {
        StatMessage::Event {
            action: StatAction::Blocked(bits),
            ..
        } => {
            assert!(
                bits & REASON_STATIC_BLACKLIST != 0,
                "static blocklist block must carry STATIC_BLACKLIST reason, got bits: 0x{bits:04x}"
            );
        }
        other => panic!("expected Blocked event, got: {other:?}"),
    }
}

#[test]
fn idn_block_stats_carries_suspicious_idn_reason() {
    // hickory's Name::to_string() decodes punycode to Unicode, so
    // "xn--pple-43d.com" arrives at the filters as "аpple.com" (non-ASCII).
    // With force_lowercase_ascii=true that hits InvalidStructure first.
    // Use start_with_idn_check() (force_lowercase_ascii=false) so the
    // structure gate is bypassed and is_illegal_idn() can fire instead.
    let srv = TestServer::start_with_idn_check("list_domain.txt");
    let mut stats = srv.connect_stats();
    drain_pending_messages(&mut stats);

    let _ = srv.query("xn--pple-43d.com", QTYPE_A);

    let _mapping = read_stat_message(&mut stats).expect("expected DomainMapping");
    let event = read_stat_message(&mut stats).expect("expected Event");

    match event {
        StatMessage::Event {
            action: StatAction::Blocked(bits),
            ..
        } => {
            assert!(
                bits & REASON_SUSPICIOUS_IDN != 0,
                "IDN block must carry SUSPICIOUS_IDN reason, got bits: 0x{bits:04x}"
            );
        }
        other => panic!("expected Blocked event for IDN domain, got: {other:?}"),
    }
}

#[test]
fn forbidden_qtype_stats_carries_forbidden_qtype_reason() {
    // Use a domain other than "example.com" (the wait_ready probe) so the
    // domain hash is fresh after the drain and produces a DomainMapping.
    let srv = TestServer::start("list_domain.txt");
    let mut stats = srv.connect_stats();
    drain_pending_messages(&mut stats);

    let _ = srv.query("qtype-warden.local", QTYPE_ANY);

    let _mapping = read_stat_message(&mut stats).expect("expected DomainMapping");
    let event = read_stat_message(&mut stats).expect("expected Event");

    match event {
        StatMessage::Event {
            action: StatAction::Blocked(bits),
            ..
        } => {
            assert!(
                bits & REASON_FORBIDDEN_QTYPE != 0,
                "QType block must carry FORBIDDEN_QTYPE reason, got bits: 0x{bits:04x}"
            );
        }
        other => panic!("expected Blocked event for forbidden QType, got: {other:?}"),
    }
}

#[test]
fn high_entropy_stats_carries_high_entropy_reason() {
    let srv = TestServer::start("list_domain.txt");
    let mut stats = srv.connect_stats();
    drain_pending_messages(&mut stats);

    let _ = srv.query("a1b2c3d4e5f6g7h8i9j0.com", QTYPE_A);

    let _mapping = read_stat_message(&mut stats).expect("expected DomainMapping");
    let event = read_stat_message(&mut stats).expect("expected Event");

    match event {
        StatMessage::Event {
            action: StatAction::Blocked(bits),
            ..
        } => {
            assert!(
                bits & REASON_HIGH_ENTROPY != 0,
                "DGA block must carry HIGH_ENTROPY reason, got bits: 0x{bits:04x}"
            );
        }
        other => panic!("expected Blocked event for DGA domain, got: {other:?}"),
    }
}

#[test]
fn domain_hash_is_consistent_across_mapping_and_event() {
    let srv = TestServer::start("list_domain.txt");
    let mut stats = srv.connect_stats();
    drain_pending_messages(&mut stats);

    let _ = srv.query("samsungads.com", QTYPE_A);

    let mapping_hash = match read_stat_message(&mut stats).expect("expected DomainMapping") {
        StatMessage::DomainMapping { hash, .. } => hash,
        other => panic!("expected DomainMapping, got: {other:?}"),
    };

    let event_hash = match read_stat_message(&mut stats).expect("expected Event") {
        StatMessage::Event { domain_hash, .. } => domain_hash,
        other => panic!("expected Event, got: {other:?}"),
    };

    assert_eq!(
        mapping_hash, event_hash,
        "domain hash in DomainMapping must match hash in Event"
    );
}
