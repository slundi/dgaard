//! End-to-end integration tests — dgaard + dgaard-monitor together.
//!
//! Each test spawns a real dgaard process (DNS proxy) and a real dgaard-monitor
//! process, sends DNS queries to dgaard, and asserts that the resulting events
//! appear correctly in dgaard-monitor's REST API (`/api/v1/queries` and
//! `/api/v1/stats`).
//!
//! Prerequisites: build the whole workspace before running.
//!   cargo build --workspace
//!   cargo nextest run --test e2e_monitor_test

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Timing constants
// ---------------------------------------------------------------------------

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Port / path allocation — unique across parallel tests in the same process
// ---------------------------------------------------------------------------

static TEST_COUNTER: AtomicU32 = AtomicU32::new(2000);

fn next_test_id() -> u32 {
    TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn find_free_udp_port() -> u16 {
    // Bind to :0 → OS assigns an ephemeral port → release it.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("cannot bind UDP :0");
    sock.local_addr().unwrap().port()
}

fn find_free_tcp_port() -> u16 {
    use std::net::TcpListener;
    let l = TcpListener::bind("127.0.0.1:0").expect("cannot bind TCP :0");
    l.local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------
// Temp directory — deleted on drop
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(id: u32) -> Self {
        let path = std::env::temp_dir().join(format!("dgaard_e2e_{}_{}", std::process::id(), id));
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
// DNS packet helpers
// ---------------------------------------------------------------------------

const QTYPE_A: u16 = 1;
const QTYPE_ANY: u16 = 255;

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
    fn start(blocklist_filename: &str) -> Self {
        let id = next_test_id();
        let dir = TempDir::new(id);
        let port = find_free_udp_port();
        let socket_path = dir.path().join("stats.sock");
        let config_path = dir.path().join("dgaard.toml");

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
force_lowercase_ascii = true

[sources]
blacklists = ["{blocklist}"]
"#,
            port = port,
            socket = socket_path.display(),
            blocklist = blocklist_path.display(),
        );

        fs::write(&config_path, &config).expect("failed to write dgaard config");

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

    fn wait_ready(&self) {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", self.port).parse().unwrap();
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
                // Use a blocked domain so the probe is served locally (no upstream
                // round-trip) and no hot-cache entry is created for clean domains
                // that tests may later query to verify non-blocked behaviour.
                let probe = build_dns_query(0xBEEF, "samsungads.com", QTYPE_A);
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

    fn query(&self, domain: &str, qtype: u16) {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", self.port).parse().unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind client socket");
        sock.set_read_timeout(Some(QUERY_TIMEOUT))
            .expect("set read timeout");
        let pkt = build_dns_query(0x1234, domain, qtype);
        sock.send_to(&pkt, addr).expect("send query");
        let mut buf = [0u8; 4096];
        let _ = sock.recv_from(&mut buf); // response not checked here; only stats matter
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// MonitorServer — wraps a spawned dgaard-monitor child process
// ---------------------------------------------------------------------------

/// Locate the dgaard-monitor binary.
///
/// Under `cargo nextest run` the binary is co-located with the dgaard binary
/// in the same `target/<profile>/` directory.
///
/// Under `cargo llvm-cov` a separate target dir (`llvm-cov-target/`) is used
/// and only transitive dependencies of the tested crate are built there —
/// dgaard-monitor is not one of them.  We fall back to the workspace's default
/// `target/<profile>/` directory.  The monitor does not need to be
/// coverage-instrumented; only the code under test (dgaard) does.
///
/// **Important**: do NOT spawn `cargo build` from inside a test.  Doing so
/// inherits llvm-cov's `RUSTFLAGS`, rewrites workspace artifacts mid-run, and
/// corrupts other crates' binary paths (causing their tests to fail with
/// "No such file or directory").  Instead, require the binary to be pre-built
/// — the `coverage-check` justfile target does this automatically.
fn monitor_bin() -> PathBuf {
    let dgaard = env!("CARGO_BIN_EXE_dgaard");
    let bin_dir = Path::new(dgaard)
        .parent()
        .expect("dgaard binary must have a parent directory");

    // 1. Happy path: co-located binary (normal `cargo nextest run`).
    let co_located = bin_dir.join("dgaard-monitor");
    if co_located.exists() {
        return co_located;
    }

    // 2. Fallback: default target/<profile>/ directory.
    //    `bin_dir` is `…/target/<tool-dir>/<profile>/`; the profile name is
    //    its last path component ("debug" or "release").
    let profile = bin_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("debug");
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dgaard crate must be inside the workspace");
    let default_bin = workspace_root
        .join("target")
        .join(profile)
        .join("dgaard-monitor");

    if default_bin.exists() {
        return default_bin;
    }

    panic!(
        "dgaard-monitor binary not found.\n\
         Searched:\n  {co_located:?}\n  {default_bin:?}\n\
         Run `cargo build -p dgaard-monitor` before executing these tests \
         (the `coverage-check` justfile target does this automatically)."
    )
}

struct MonitorServer {
    pub web_port: u16,
    child: Child,
    _dir: TempDir,
}

impl MonitorServer {
    /// Spawn dgaard-monitor in headless mode, connected to `stats_socket`,
    /// with the web API enabled on an ephemeral TCP port.
    fn start(stats_socket: &Path) -> Self {
        let id = next_test_id();
        let dir = TempDir::new(id);
        let web_port = find_free_tcp_port();
        let db_path = dir.path().join("stats.db");
        let config_path = dir.path().join("monitor.toml");

        let config = format!(
            r#"
[input]
socket = "{socket}"
index = "/nonexistent/hosts.bin"

[persistence]
db = "{db}"
events_retention_hours = 72
aggregates_retention_days = 90

[web]
enabled = true
listen = "127.0.0.1"
port = {port}
token = ""
history_size = 5000
"#,
            socket = stats_socket.display(),
            db = db_path.display(),
            port = web_port,
        );

        fs::write(&config_path, &config).expect("failed to write monitor config");

        let child = Command::new(monitor_bin())
            .arg("--config")
            .arg(&config_path)
            .arg("--headless")
            .spawn()
            .expect("failed to spawn dgaard-monitor");

        let monitor = Self {
            web_port,
            child,
            _dir: dir,
        };
        monitor.wait_ready();
        monitor
    }

    /// Poll `GET /api/v1/health` (returns 204) until the web server is up.
    fn wait_ready(&self) {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if Instant::now() > deadline {
                panic!(
                    "dgaard-monitor web API on port {} did not become ready within {:?}",
                    self.web_port, STARTUP_TIMEOUT
                );
            }
            if let Ok((204, _)) = http_get_inner(self.web_port, "/api/v1/health") {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for MonitorServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Minimal blocking HTTP/1.0 client
// ---------------------------------------------------------------------------

/// Issue a GET request and return `(status_code, body)`.
/// Uses HTTP/1.0 to avoid chunked transfer encoding.
fn http_get(port: u16, path: &str) -> (u16, String) {
    http_get_inner(port, path).unwrap_or_else(|e| panic!("http_get({port}, {path}): {e}"))
}

fn http_get_inner(port: u16, path: &str) -> Result<(u16, String), String> {
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let request = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    let mut reader = BufReader::new(stream);

    // Status line: "HTTP/1.0 200 OK\r\n"
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| format!("read status: {e}"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Skip response headers
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read header: {e}"))?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    // Read body
    let mut body = String::new();
    reader
        .read_to_string(&mut body)
        .map_err(|e| format!("read body: {e}"))?;

    Ok((status, body))
}

// ---------------------------------------------------------------------------
// Polling helpers
// ---------------------------------------------------------------------------

/// Poll `GET /api/v1/queries` until at least one event satisfies `predicate`.
///
/// Returns all matching events. Panics with a diagnostic dump if no match
/// appears before `timeout` expires.
fn poll_for_event(
    monitor: &MonitorServer,
    timeout: Duration,
    predicate: impl Fn(&serde_json::Value) -> bool,
) -> Vec<serde_json::Value> {
    let deadline = Instant::now() + timeout;
    loop {
        let (status, body) = http_get(monitor.web_port, "/api/v1/queries");
        if status == 200
            && let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&body)
        {
            let matches: Vec<_> = arr.into_iter().filter(|v| predicate(v)).collect();
            if !matches.is_empty() {
                return matches;
            }
        }
        if Instant::now() > deadline {
            let (_, last) = http_get(monitor.web_port, "/api/v1/queries");
            panic!(
                "monitor did not receive the expected event within {timeout:?}.\
                \nLast /api/v1/queries response:\n{last}"
            );
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn e2e_blocked_domain_appears_in_monitor_queries() {
    let srv = TestServer::start("list_domain.txt");
    let monitor = MonitorServer::start(&srv.socket_path);

    srv.query("samsungads.com", QTYPE_A);

    let events = poll_for_event(&monitor, EVENT_TIMEOUT, |v| {
        v["domain"].as_str() == Some("samsungads.com") && v["action"].as_str() == Some("Blocked")
    });

    let ev = &events[0];
    assert!(
        ev["flags"].is_number(),
        "Blocked event must carry a flags bitmask, got: {ev}"
    );
    let labels = ev["flags_labels"]
        .as_array()
        .expect("flags_labels must be an array");
    assert!(
        labels
            .iter()
            .any(|l| l.as_str() == Some("STATIC_BLACKLIST")),
        "STATIC_BLACKLIST must be in block reasons, got: {labels:?}"
    );
}

#[test]
fn e2e_high_entropy_domain_blocked_with_correct_flag() {
    let srv = TestServer::start("list_domain.txt");
    let monitor = MonitorServer::start(&srv.socket_path);

    // "a1b2c3d4e5f6g7h8i9j0.com" has Shannon entropy > 4.0
    srv.query("a1b2c3d4e5f6g7h8i9j0.com", QTYPE_A);

    let events = poll_for_event(&monitor, EVENT_TIMEOUT, |v| {
        v["domain"].as_str() == Some("a1b2c3d4e5f6g7h8i9j0.com")
            && v["action"].as_str() == Some("Blocked")
    });

    let labels = events[0]["flags_labels"]
        .as_array()
        .expect("flags_labels must be an array");
    assert!(
        labels.iter().any(|l| l.as_str() == Some("HIGH_ENTROPY")),
        "HIGH_ENTROPY must be in block reasons, got: {labels:?}"
    );
}

#[test]
fn e2e_forbidden_qtype_blocked_with_correct_flag() {
    let srv = TestServer::start("list_domain.txt");
    let monitor = MonitorServer::start(&srv.socket_path);

    // ANY query (type 255) is blocked by the QType Warden
    srv.query("qtype-warden-e2e.example", QTYPE_ANY);

    let events = poll_for_event(&monitor, EVENT_TIMEOUT, |v| {
        v["domain"].as_str() == Some("qtype-warden-e2e.example")
            && v["action"].as_str() == Some("Blocked")
    });

    let labels = events[0]["flags_labels"]
        .as_array()
        .expect("flags_labels must be an array");
    assert!(
        labels.iter().any(|l| l.as_str() == Some("FORBIDDEN_QTYPE")),
        "FORBIDDEN_QTYPE must be in block reasons, got: {labels:?}"
    );
}

#[test]
fn e2e_multiple_blocked_domains_all_appear_in_monitor() {
    let srv = TestServer::start("list_domain.txt");
    let monitor = MonitorServer::start(&srv.socket_path);

    let domains = ["samsungads.com", "smartclip.net", "yumenetworks.com"];
    for domain in &domains {
        srv.query(domain, QTYPE_A);
    }

    for domain in &domains {
        let d = *domain;
        poll_for_event(&monitor, EVENT_TIMEOUT, |v| {
            v["domain"].as_str() == Some(d) && v["action"].as_str() == Some("Blocked")
        });
    }
}

#[test]
fn e2e_monitor_stats_blocked_count_reflects_queries() {
    let srv = TestServer::start("list_domain.txt");
    let monitor = MonitorServer::start(&srv.socket_path);

    srv.query("samsungads.com", QTYPE_A);
    srv.query("smartclip.net", QTYPE_A);
    srv.query("yumenetworks.com", QTYPE_A);

    // Wait for all three events to appear in the query log before reading stats
    for domain in &["samsungads.com", "smartclip.net", "yumenetworks.com"] {
        let d = *domain;
        poll_for_event(&monitor, EVENT_TIMEOUT, |v| v["domain"].as_str() == Some(d));
    }

    let (status, body) = http_get(monitor.web_port, "/api/v1/stats");
    assert_eq!(status, 200, "stats endpoint must return 200");

    let stats: serde_json::Value = serde_json::from_str(&body).expect("stats must be valid JSON");

    let total = stats["total"].as_u64().expect("total must be a number");
    let blocked = stats["blocked"].as_u64().expect("blocked must be a number");

    assert!(
        total >= 3,
        "total event count must be at least 3, got: {total}"
    );
    assert!(
        blocked >= 3,
        "blocked event count must be at least 3, got: {blocked}"
    );

    // blocked_pct must be a non-empty string and not "0.0%"
    let pct = stats["blocked_pct"]
        .as_str()
        .expect("blocked_pct must be a string");
    assert_ne!(
        pct, "0.0%",
        "blocked_pct must not be zero when there are blocked events"
    );
}

#[test]
fn e2e_domain_name_is_resolved_in_monitor_event() {
    let srv = TestServer::start("list_domain.txt");
    let monitor = MonitorServer::start(&srv.socket_path);

    // dgaard sends a DomainMapping frame before the Event frame, so the monitor
    // should always be able to resolve the domain name even without an index file.
    srv.query("samsungads.com", QTYPE_A);

    let events = poll_for_event(&monitor, EVENT_TIMEOUT, |v| {
        v["domain"].as_str() == Some("samsungads.com")
    });

    let ev = &events[0];
    assert_eq!(
        ev["domain"].as_str(),
        Some("samsungads.com"),
        "domain field must be resolved from the DomainMapping frame"
    );

    // domain_hash must be a 16-char hex string
    let hash = ev["domain_hash"]
        .as_str()
        .expect("domain_hash must be a string");
    assert_eq!(hash.len(), 16, "domain_hash must be 16 hex digits");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "domain_hash must only contain hex digits"
    );
}

#[test]
fn e2e_non_blocked_domain_appears_without_blocked_action() {
    let srv = TestServer::start("list_domain.txt");
    let monitor = MonitorServer::start(&srv.socket_path);

    // Warm up: confirm the monitor-to-dgaard socket connection is live before
    // sending the non-blocked query.  Under `cargo test` (used by llvm-cov),
    // tests run in parallel threads; the monitor's socket-connect tokio task
    // may not have been scheduled yet when `start()` returns.  A blocked
    // domain is handled locally (no upstream DNS), so this event arrives
    // quickly and proves the pipeline is connected end-to-end.
    srv.query("samsungads.com", QTYPE_A);
    poll_for_event(&monitor, EVENT_TIMEOUT, |v| {
        v["domain"].as_str() == Some("samsungads.com")
    });

    // example.com is not in any blocklist; it will be Allowed or Proxied.
    srv.query("example.com", QTYPE_A);

    let events = poll_for_event(&monitor, EVENT_TIMEOUT, |v| {
        v["domain"].as_str() == Some("example.com")
    });

    let action = events[0]["action"].as_str().unwrap_or("");
    assert!(
        action == "Allowed" || action == "Proxied",
        "example.com must not be Blocked; got action: '{action}'"
    );
    assert!(
        events[0]["flags"].is_null(),
        "Allowed/Proxied events must have null flags, got: {}",
        events[0]["flags"]
    );
}
