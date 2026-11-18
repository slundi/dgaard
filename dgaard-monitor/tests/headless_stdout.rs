//! End-to-end check of the headless contract: stdout carries one JSON object
//! per event and nothing else, so log shippers can ingest it as-is.
//! Diagnostics belong on stderr, and the forwarding sink must not write to
//! stdout when no `file` is configured.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatEvent, StatMessage};

const TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn headless_stdout_is_pure_json() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("stats.sock");
    let config_path = dir.path().join("monitor.toml");
    let listener = UnixListener::bind(&socket_path).unwrap();

    // `[forwarding]` without `file` mirrors the example config: forwarding
    // used to fall back to stdout here and duplicate every event.
    let config = format!(
        r#"
[input]
socket = "{socket}"
index = "{index}"

[persistence]
db = "{db}"

[forwarding]
template = "{{timestamp}} {{client_ip}} {{action}} {{domain}}"
filter = []
"#,
        socket = socket_path.display(),
        index = dir.path().join("missing-index.bin").display(),
        db = dir.path().join("stats.sqlite").display(),
    );
    std::fs::write(&config_path, config).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_dgaard-monitor"))
        .arg("--headless")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let (line_tx, line_rx) = mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    let stdout_reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    let stderr_reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });

    // Play the dgaard daemon: accept the monitor and send one mapping + one event.
    let (accept_tx, accept_rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = accept_tx.send(listener.accept().map(|(stream, _)| stream));
    });
    let mut stream = match accept_rx.recv_timeout(TIMEOUT) {
        Ok(Ok(stream)) => stream,
        other => {
            let _ = child.kill();
            panic!("monitor never connected to the socket: {other:?}");
        }
    };
    let mapping = StatMessage::DomainMapping {
        hash: 7,
        domain: "one.test".to_string(),
    };
    let event = StatMessage::Event(StatEvent {
        timestamp: 1_700_000_000,
        domain_hash: 7,
        client_ip: std::net::Ipv4Addr::new(10, 0, 0, 1)
            .to_ipv6_mapped()
            .octets(),
        action: StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST),
    });
    stream.write_all(&mapping.serialize()).unwrap();
    stream.write_all(&event.serialize()).unwrap();
    stream.flush().unwrap();

    let mut lines = Vec::new();
    match line_rx.recv_timeout(TIMEOUT) {
        Ok(line) => lines.push(line),
        Err(_) => {
            let _ = child.kill();
            panic!("no event line on stdout");
        }
    }
    // Leave time for any duplicate (e.g. a forwarding line) to show up.
    while let Ok(line) = line_rx.recv_timeout(Duration::from_millis(500)) {
        lines.push(line);
    }

    child.kill().unwrap();
    child.wait().unwrap();
    drop(stream);
    stdout_reader.join().unwrap();
    lines.extend(line_rx.try_iter());
    let stderr_text = stderr_reader.join().unwrap();

    for line in &lines {
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_ok(),
            "non-JSON line on stdout: {line:?}\nall stdout: {lines:#?}"
        );
    }
    assert_eq!(lines.len(), 1, "expected exactly one event: {lines:#?}");
    let record: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(record["domain"], "one.test");
    assert_eq!(record["action"], "Blocked");
    // dgaard sends IPv4 clients as `::ffff:a.b.c.d`; outputs show `a.b.c.d`.
    assert_eq!(record["client_ip"], "10.0.0.1");

    assert!(
        stderr_text.contains("Connected to"),
        "diagnostics should go to stderr, got: {stderr_text:?}"
    );
}
