//! Binary integration tests — spawn the real `dgaard-rest` process and
//! exercise all HTTP endpoints over TCP.
//!
//! These complement the in-process `tower::oneshot` tests in `api.rs` by
//! verifying that the binary correctly reads its config file, loads engine
//! state, and serves HTTP over the configured listen address.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use tempfile::TempDir;

// ── Port allocation ───────────────────────────────────────────────────────────

/// Bind to port 0 to let the OS pick a free ephemeral port, note it, then
/// release the listener so dgaard-rest can bind to the same port.
fn next_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

// ── Paths ─────────────────────────────────────────────────────────────────────

fn rest_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dgaard-rest"))
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

// ── RestServer ────────────────────────────────────────────────────────────────

struct RestServer {
    pub port: u16,
    child: Child,
    _dir: TempDir,
}

impl RestServer {
    /// Spawn `dgaard-rest` with an optional blocklist and `blocked_status_code`.
    ///
    /// Blocks until the health endpoint returns 204 or panics after 10 s.
    fn start(port: u16, blocklist: Option<&Path>, blocked_status_code: u16) -> Self {
        let dir = TempDir::new().expect("tempdir");

        // Engine config — explicitly clear all default source paths so the test
        // is isolated from EngineConfig::default() values that would otherwise
        // add /etc/dgaard/… blacklists, whitelists, and the NRD list.
        let engine_cfg = dir.path().join("engine.toml");
        let blacklists_toml = match blocklist {
            Some(bl) => format!("\"{}\"", bl.to_string_lossy()),
            None => String::new(),
        };
        let engine_toml = format!(
            "[sources]\nblacklists = [{blacklists_toml}]\nwhitelists = []\nnrd_list_path = \"\"\nbrowser_rules_path = \"\"\n"
        );
        std::fs::write(&engine_cfg, engine_toml).expect("write engine config");

        // REST server config.
        let rest_cfg = dir.path().join("dgaard-rest.toml");
        std::fs::write(
            &rest_cfg,
            format!(
                "listen_addr = \"127.0.0.1:{port}\"\nconfig_file = \"{engine}\"\nlog_level = \"warn\"\nblocked_status_code = {code}\n",
                engine = engine_cfg.to_string_lossy(),
                code = blocked_status_code,
            ),
        )
        .expect("write rest config");

        let child = Command::new(rest_bin())
            .args(["--config", rest_cfg.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dgaard-rest");

        let srv = Self {
            port,
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
                "dgaard-rest did not become ready on port {} within {:?}",
                self.port,
                timeout
            );
            if http_get(self.port, "/api/v1/health").0 == 204 {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for RestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn http_get(port: u16, path: &str) -> (u16, String) {
    http_request(port, "GET", path, None).unwrap_or_else(|e| (0, e))
}

fn http_post_json(port: u16, path: &str, body: &str) -> (u16, String) {
    http_request(port, "POST", path, Some(body)).unwrap_or_else(|e| (0, e))
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    json_body: Option<&str>,
) -> Result<(u16, String), String> {
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    {
        let mut w = std::io::BufWriter::new(stream.try_clone().unwrap());
        if let Some(body) = json_body {
            write!(
                w,
                "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\r\n{body}",
                len = body.len(),
            )
            .map_err(|e| e.to_string())?;
        } else {
            write!(w, "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                .map_err(|e| e.to_string())?;
        }
        w.flush().map_err(|e| e.to_string())?;
    }

    let mut reader = BufReader::new(stream);

    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| e.to_string())?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("unparsable status line: {status_line:?}"))?;

    // Drain headers until blank line.
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    let mut body = String::new();
    reader
        .read_to_string(&mut body)
        .map_err(|e| e.to_string())?;
    Ok((status, body))
}

// ── GET /api/v1/health ────────────────────────────────────────────────────────

#[test]
fn binary_health_returns_204() {
    let srv = RestServer::start(next_port(), None, 200);
    let (status, _) = http_get(srv.port, "/api/v1/health");
    assert_eq!(status, 204);
}

// ── POST /api/v1/check ────────────────────────────────────────────────────────

#[test]
fn binary_check_clean_domain_not_blocked() {
    let srv = RestServer::start(next_port(), None, 200);
    let (status, body) = http_post_json(srv.port, "/api/v1/check", r#"{"domain":"example.com"}"#);
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        json["blocked"], false,
        "expected blocked=false, got: {json}"
    );
    assert_eq!(json["domain"], "example.com");
}

#[test]
fn binary_check_response_has_all_required_fields() {
    let srv = RestServer::start(next_port(), None, 200);
    let (_, body) = http_post_json(srv.port, "/api/v1/check", r#"{"domain":"example.com"}"#);
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    for field in ["domain", "score", "blocked", "action", "reasons"] {
        assert!(
            json.get(field).is_some(),
            "missing field '{field}' in response: {json}"
        );
    }
    assert!(json["reasons"].is_array());
}

#[test]
fn binary_check_blocklisted_domain_is_blocked() {
    let fixture = blocklist_fixture();
    let srv = RestServer::start(next_port(), Some(&fixture), 200);
    // ads.samsungads.com is present in the Smart-TV fixture list.
    let (status, body) = http_post_json(
        srv.port,
        "/api/v1/check",
        r#"{"domain":"ads.samsungads.com"}"#,
    );
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(json["blocked"], true, "expected blocked=true, got: {json}");
}

#[test]
fn binary_check_blocklisted_domain_returns_403_when_configured() {
    let fixture = blocklist_fixture();
    let srv = RestServer::start(next_port(), Some(&fixture), 403);
    let (status, body) = http_post_json(
        srv.port,
        "/api/v1/check",
        r#"{"domain":"ads.samsungads.com"}"#,
    );
    assert_eq!(status, 403, "expected HTTP 403, got {status}: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(json["blocked"], true);
}

#[test]
fn binary_check_missing_domain_returns_400() {
    let srv = RestServer::start(next_port(), None, 200);
    let (status, _) = http_post_json(srv.port, "/api/v1/check", "{}");
    assert_eq!(status, 400);
}

#[test]
fn binary_check_empty_domain_returns_400() {
    let srv = RestServer::start(next_port(), None, 200);
    let (status, _) = http_post_json(srv.port, "/api/v1/check", r#"{"domain":""}"#);
    assert_eq!(status, 400);
}

#[test]
fn binary_check_domain_too_long_returns_422() {
    let srv = RestServer::start(next_port(), None, 200);
    let domain = "a".repeat(254);
    let body = format!(r#"{{"domain":"{domain}"}}"#);
    let (status, _) = http_post_json(srv.port, "/api/v1/check", &body);
    assert_eq!(status, 422);
}

// ── GET /api/v1/blocklists ────────────────────────────────────────────────────

#[test]
fn binary_get_blocklists_returns_json_array() {
    let srv = RestServer::start(next_port(), None, 200);
    let (status, body) = http_get(srv.port, "/api/v1/blocklists");
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert!(json.is_array(), "expected JSON array, got: {json}");
}

#[test]
fn binary_get_blocklists_with_fixture_shows_nonzero_count() {
    let fixture = blocklist_fixture();
    let srv = RestServer::start(next_port(), Some(&fixture), 200);
    let (status, body) = http_get(srv.port, "/api/v1/blocklists");
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let arr = json.as_array().expect("array");
    assert_eq!(arr.len(), 1, "one configured blocklist");
    assert!(
        arr[0]["count"].as_u64().unwrap_or(0) > 0,
        "expected non-zero domain count, got: {}",
        arr[0]
    );
}

#[test]
fn binary_get_blocklists_entry_has_required_fields() {
    let fixture = blocklist_fixture();
    let srv = RestServer::start(next_port(), Some(&fixture), 200);
    let (_, body) = http_get(srv.port, "/api/v1/blocklists");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let entry = &json.as_array().unwrap()[0];
    for field in ["name", "count", "last_updated"] {
        assert!(
            entry.get(field).is_some(),
            "missing field '{field}' in blocklist entry: {entry}"
        );
    }
}

// ── POST /api/v1/blocklists/update ───────────────────────────────────────────

#[test]
fn binary_post_blocklists_update_returns_202() {
    let srv = RestServer::start(next_port(), None, 200);
    // The update endpoint takes no body.
    let (status, _) = http_post_json(srv.port, "/api/v1/blocklists/update", "");
    assert_eq!(status, 202);
}
