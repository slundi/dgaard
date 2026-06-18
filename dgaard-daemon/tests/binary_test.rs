//! Binary integration tests — spawn the real `dgaard-daemon` process and
//! communicate over its Unix domain socket.
//!
//! These complement the in-process tests in `socket.rs` by verifying that the
//! binary correctly reads its config file, loads engine state, and handles
//! queries over the actual socket it creates on disk. Each test also covers
//! behaviour that is only meaningful at the process level: SIGHUP reload and
//! graceful SIGTERM cleanup.

use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use tempfile::TempDir;

// ── Binary path helpers ───────────────────────────────────────────────────────

fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dgaard-daemon"))
}

/// Smart-TV domain blocklist shipped with the dgaard test suite.
fn blocklist_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("dgaard")
        .join("tests")
        .join("list_domain.txt")
}

// ── Engine config helpers ─────────────────────────────────────────────────────

/// Minimal engine TOML that clears all EngineConfig::default() source paths
/// (which point to /etc/dgaard/…) so tests are isolated from the filesystem.
/// Pass `Some(path)` to add one real blacklist entry.
fn engine_toml(blacklist: Option<&Path>) -> String {
    let bl = match blacklist {
        Some(p) => format!("[\"{}\"]", p.to_string_lossy()),
        None => "[]".to_string(),
    };
    format!(
        "[sources]\nblacklists = {bl}\nwhitelists = []\nnrd_list_path = \"\"\nbrowser_rules_path = \"\"\n"
    )
}

// ── DaemonServer ──────────────────────────────────────────────────────────────

struct DaemonServer {
    pub socket_path: PathBuf,
    child: Child,
    _dir: TempDir,
}

impl DaemonServer {
    /// Spawn `dgaard-daemon` with the given engine config TOML string.
    ///
    /// Blocks until the Unix socket appears on disk (daemon ready) or panics
    /// after 10 s.
    fn start(engine_config: &str) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let socket_path = dir.path().join("dgaard.sock");
        let engine_cfg = dir.path().join("engine.toml");
        std::fs::write(&engine_cfg, engine_config).expect("write engine config");

        let daemon_cfg = dir.path().join("dgaard-daemon.toml");
        std::fs::write(
            &daemon_cfg,
            format!(
                "socket_path = \"{sock}\"\nconfig_file = \"{eng}\"\nlog_level = \"warn\"\n",
                sock = socket_path.to_string_lossy(),
                eng = engine_cfg.to_string_lossy(),
            ),
        )
        .expect("write daemon config");

        let child = Command::new(daemon_bin())
            .args(["--config", daemon_cfg.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dgaard-daemon");

        let srv = Self {
            socket_path,
            child,
            _dir: dir,
        };
        srv.wait_ready(Duration::from_secs(10));
        srv
    }

    fn wait_ready(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            assert!(
                Instant::now() < deadline,
                "dgaard-daemon socket did not appear within {:?}",
                timeout
            );
            if self.socket_path.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for DaemonServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Socket query helper ───────────────────────────────────────────────────────

/// Connect to the daemon socket, send `domain\n`, return the parsed JSON response.
fn query(socket_path: &Path, domain: &str) -> serde_json::Value {
    let mut stream = UnixStream::connect(socket_path).expect("connect to daemon socket");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    writeln!(stream, "{domain}").expect("send domain");
    stream.flush().expect("flush");

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).expect("read response");
    serde_json::from_str(response.trim()).expect("valid JSON response")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// --- Startup ---

#[test]
fn binary_daemon_creates_socket_on_startup() {
    let srv = DaemonServer::start(&engine_toml(None));
    assert!(
        srv.socket_path.exists(),
        "socket file should exist after startup"
    );
}

// --- Query behaviour ---

#[test]
fn binary_query_clean_domain_not_blocked() {
    let srv = DaemonServer::start(&engine_toml(None));
    let json = query(&srv.socket_path, "example.com");
    assert_eq!(json["blocked"], false, "expected blocked=false: {json}");
    assert_eq!(
        json["action"], "ProxyToUpstream",
        "expected ProxyToUpstream: {json}"
    );
}

#[test]
fn binary_query_response_has_required_fields() {
    let srv = DaemonServer::start(&engine_toml(None));
    let json = query(&srv.socket_path, "example.com");
    for field in ["score", "blocked", "action", "reasons"] {
        assert!(
            json.get(field).is_some(),
            "missing field '{field}' in: {json}"
        );
    }
    assert!(json["reasons"].is_array());
}

#[test]
fn binary_query_structural_block() {
    let srv = DaemonServer::start(&engine_toml(None));
    // 7 dots exceeds the default max_subdomain_depth of 5.
    let json = query(&srv.socket_path, "a.b.c.d.e.f.g.example.com");
    assert_eq!(json["blocked"], true, "expected blocked=true: {json}");
    assert!(
        json["action"]
            .as_str()
            .unwrap_or("")
            .contains("InvalidStructure"),
        "expected InvalidStructure action: {json}"
    );
}

#[test]
fn binary_query_blocklisted_domain_returns_static_blacklist() {
    let srv = DaemonServer::start(&engine_toml(Some(&blocklist_fixture())));
    // ads.samsungads.com is present in the Smart-TV fixture list.
    let json = query(&srv.socket_path, "ads.samsungads.com");
    assert_eq!(json["blocked"], true, "expected blocked=true: {json}");
    assert!(
        json["action"]
            .as_str()
            .unwrap_or("")
            .contains("StaticBlacklist"),
        "expected StaticBlacklist action: {json}"
    );
}

#[test]
fn binary_clean_domain_not_blocked_with_real_blocklist() {
    let srv = DaemonServer::start(&engine_toml(Some(&blocklist_fixture())));
    let json = query(&srv.socket_path, "example.com");
    assert_eq!(json["blocked"], false, "expected blocked=false: {json}");
}

#[test]
fn binary_multiple_sequential_queries_all_succeed() {
    let srv = DaemonServer::start(&engine_toml(None));
    let domains = ["example.com", "google.com", "rust-lang.org", "github.com"];
    for domain in domains {
        let json = query(&srv.socket_path, domain);
        assert!(
            json.get("blocked").is_some(),
            "query '{domain}' returned no 'blocked' field: {json}"
        );
    }
}

#[test]
fn binary_error_on_empty_domain() {
    let srv = DaemonServer::start(&engine_toml(None));
    // Send a bare newline — empty domain.
    let mut stream = UnixStream::connect(&srv.socket_path).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    writeln!(stream).expect("send");
    stream.flush().expect("flush");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read");
    let json: serde_json::Value = serde_json::from_str(line.trim()).expect("valid JSON");
    assert!(
        json.get("error").is_some(),
        "expected error key for empty domain: {json}"
    );
}

// --- SIGHUP reload ---

#[test]
fn binary_sighup_reloads_engine_config() {
    let dir = TempDir::new().expect("tempdir");
    let socket_path = dir.path().join("dgaard.sock");
    let engine_cfg = dir.path().join("engine.toml");

    // Start with a strict structural config: max_subdomain_depth = 2.
    // a.b.c.example.com has 4 dots, so it will be blocked.
    std::fs::write(
        &engine_cfg,
        "[sources]\nblacklists = []\nwhitelists = []\nnrd_list_path = \"\"\nbrowser_rules_path = \"\"\n[security.structure]\nmax_subdomain_depth = 2\n",
    )
    .expect("write initial engine config");

    let daemon_cfg = dir.path().join("dgaard-daemon.toml");
    std::fs::write(
        &daemon_cfg,
        format!(
            "socket_path = \"{sock}\"\nconfig_file = \"{eng}\"\nlog_level = \"warn\"\n",
            sock = socket_path.to_string_lossy(),
            eng = engine_cfg.to_string_lossy(),
        ),
    )
    .expect("write daemon config");

    let mut child = Command::new(daemon_bin())
        .args(["--config", daemon_cfg.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dgaard-daemon");

    // Wait for socket.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket_path.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(20));
    }

    // Confirm the domain is blocked under the strict config.
    let before = query(&socket_path, "a.b.c.example.com");
    assert_eq!(
        before["blocked"], true,
        "should be blocked with max_subdomain_depth=2: {before}"
    );

    // Overwrite the engine config with a permissive setting.
    std::fs::write(
        &engine_cfg,
        "[sources]\nblacklists = []\nwhitelists = []\nnrd_list_path = \"\"\nbrowser_rules_path = \"\"\n[security.structure]\nmax_subdomain_depth = 10\n",
    )
    .expect("write updated engine config");

    // Send SIGHUP.
    Command::new("kill")
        .args(["-HUP", &child.id().to_string()])
        .status()
        .expect("send SIGHUP");

    // Poll until the reload takes effect (or timeout after 3 s).
    let reload_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        std::thread::sleep(Duration::from_millis(100));
        let after = query(&socket_path, "a.b.c.example.com");
        if after["blocked"] == false {
            break;
        }
        assert!(
            Instant::now() < reload_deadline,
            "engine config was not reloaded within 3 s after SIGHUP"
        );
    }

    let _ = child.kill();
    let _ = child.wait();
}

// --- SIGTERM cleanup ---

#[test]
fn binary_socket_removed_after_sigterm() {
    let dir = TempDir::new().expect("tempdir");
    let socket_path = dir.path().join("dgaard.sock");
    let engine_cfg = dir.path().join("engine.toml");
    std::fs::write(&engine_cfg, engine_toml(None)).expect("write engine config");

    let daemon_cfg = dir.path().join("dgaard-daemon.toml");
    std::fs::write(
        &daemon_cfg,
        format!(
            "socket_path = \"{sock}\"\nconfig_file = \"{eng}\"\nlog_level = \"warn\"\n",
            sock = socket_path.to_string_lossy(),
            eng = engine_cfg.to_string_lossy(),
        ),
    )
    .expect("write daemon config");

    let mut child = Command::new(daemon_bin())
        .args(["--config", daemon_cfg.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dgaard-daemon");

    // Wait for socket.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket_path.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket_path.exists(), "socket should exist after startup");

    // Send SIGTERM for a graceful shutdown.
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    child.wait().expect("wait for daemon exit");

    // SocketGuard RAII should have removed the socket file.
    let cleanup_deadline = Instant::now() + Duration::from_secs(2);
    while socket_path.exists() && Instant::now() < cleanup_deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !socket_path.exists(),
        "socket file should be removed after graceful SIGTERM shutdown"
    );
}
