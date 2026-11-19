//! End-to-end check: without `--headless` and without a terminal on stdout
//! (a container started without `-t`, a systemd unit, a pipe), the monitor
//! falls back to headless output instead of a TUI that cannot draw.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use dgaard_monitor_core::protocol::{StatAction, StatEvent, StatMessage};

const TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn piped_stdout_runs_headless() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("stats.sock");
    let config_path = dir.path().join("monitor.toml");
    let listener = UnixListener::bind(&socket_path).unwrap();
    std::fs::write(
        &config_path,
        format!(
            "[input]\nsocket = \"{}\"\nindex = \"{}\"\n\n[persistence]\nenabled = false\n",
            socket_path.display(),
            dir.path().join("missing.bin").display(),
        ),
    )
    .unwrap();

    // No --headless: only the piped stdout tells the monitor to run headless.
    let mut child = Command::new(env!("CARGO_BIN_EXE_dgaard-monitor"))
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let (line_tx, line_rx) = mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
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

    let (accept_tx, accept_rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = accept_tx.send(listener.accept().map(|(stream, _)| stream));
    });
    let mut stream = match accept_rx.recv_timeout(TIMEOUT) {
        Ok(Ok(stream)) => stream,
        other => {
            let _ = child.kill();
            panic!("monitor never connected (did it exit?): {other:?}");
        }
    };
    let event = StatMessage::Event(StatEvent {
        timestamp: 1_700_000_000,
        domain_hash: 7,
        client_ip: [0; 16],
        action: StatAction::Allowed,
    });
    stream.write_all(&event.serialize()).unwrap();

    let line = line_rx.recv_timeout(TIMEOUT);
    let _ = child.kill();
    let _ = child.wait();
    let stderr_text = stderr_reader.join().unwrap();
    let line = line.unwrap_or_else(|_| panic!("no JSON event on stdout; stderr:\n{stderr_text}"));

    let record: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(record["action"], "Allowed", "{line}");
    // Without the `tui` feature the monitor is always headless: no notice.
    if cfg!(feature = "tui") {
        assert!(
            stderr_text.contains("stdout is not a terminal: running headless"),
            "{stderr_text}"
        );
    }
}
