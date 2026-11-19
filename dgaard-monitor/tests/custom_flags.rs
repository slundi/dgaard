//! End-to-end check of `[input] engine_config_path`: custom bits 16–31 are
//! labelled with the codes from the engine's `[[security.custom_flags]]`.
//! The option used to be parsed and then ignored.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatEvent, StatMessage};

const TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn custom_bits_are_labelled_from_the_engine_config() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("stats.sock");
    let engine_path = dir.path().join("dgaard.toml");
    let config_path = dir.path().join("monitor.toml");
    let listener = UnixListener::bind(&socket_path).unwrap();

    std::fs::write(
        &engine_path,
        "[[security.custom_flags]]\nbit = 20\ncode = \"AI_GENERATED\"\nlist_path = []\n",
    )
    .unwrap();
    std::fs::write(
        &config_path,
        format!(
            "[input]\nsocket = \"{}\"\nindex = \"{}\"\nengine_config_path = \"{}\"\n\n[persistence]\ndb = \"{}\"\n",
            socket_path.display(),
            dir.path().join("missing.bin").display(),
            engine_path.display(),
            dir.path().join("stats.sqlite").display(),
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_dgaard-monitor"))
        .args(["--headless", "-c"])
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
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

    let (accept_tx, accept_rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = accept_tx.send(listener.accept().map(|(stream, _)| stream));
    });
    let mut stream = match accept_rx.recv_timeout(TIMEOUT) {
        Ok(Ok(stream)) => stream,
        other => {
            let _ = child.kill();
            panic!("monitor never connected: {other:?}");
        }
    };
    let event = StatMessage::Event(StatEvent {
        country: None,
        timestamp: 1_700_000_000,
        domain_hash: 7,
        client_ip: [0; 16],
        action: StatAction::Blocked(
            StatBlockReason::from_bits_retain((1 << 20) | (1 << 21)) | StatBlockReason::NRD_LIST,
        ),
    });
    stream.write_all(&event.serialize()).unwrap();

    let line = line_rx.recv_timeout(TIMEOUT);
    let _ = child.kill();
    let _ = child.wait();
    let line = line.expect("no event on stdout");

    let record: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        record["flags_labels"],
        serde_json::json!(["NRD_LIST", "AI_GENERATED", "CUSTOM_BIT_21"]),
        "{line}"
    );
}
