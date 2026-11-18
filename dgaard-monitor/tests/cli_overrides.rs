//! End-to-end check that the `--socket`, `--index` and `--db` flags win over
//! the config file. `--db` used to be parsed and then ignored.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn path_flags_override_the_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).to_str().unwrap().to_string();
    let config_path = path("monitor.toml");
    std::fs::write(
        &config_path,
        format!(
            "[input]\nsocket = \"{}\"\nindex = \"{}\"\n\n[persistence]\ndb = \"{}\"\n",
            path("config.sock"),
            path("config.bin"),
            path("config.sqlite"),
        ),
    )
    .unwrap();
    let (flag_socket, flag_index, flag_db) =
        (path("flag.sock"), path("flag.bin"), path("flag.sqlite"));

    let mut child = Command::new(env!("CARGO_BIN_EXE_dgaard-monitor"))
        .args(["--headless", "-c", &config_path])
        .args([
            "--socket",
            &flag_socket,
            "--index",
            &flag_index,
            "--db",
            &flag_db,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let (line_tx, line_rx) = mpsc::channel();
    let stderr = child.stderr.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });

    // Each flag shows up in a startup diagnostic: missing index, opened
    // database, failed socket connection (nothing listens there).
    let expected = [
        format!("host index not found at {flag_index}"),
        format!("Persistence database opened: {flag_db}"),
        format!("connect to {flag_socket}"),
    ];
    let mut seen = [false; 3];
    let mut lines = Vec::new();
    let deadline = Instant::now() + TIMEOUT;
    while !seen.iter().all(|&found| found) {
        let Ok(line) = line_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        else {
            break;
        };
        for (found, marker) in seen.iter_mut().zip(&expected) {
            *found |= line.contains(marker.as_str());
        }
        lines.push(line);
    }

    child.kill().unwrap();
    child.wait().unwrap();

    for (found, marker) in seen.iter().zip(&expected) {
        assert!(found, "missing {marker:?} in stderr:\n{}", lines.join("\n"));
    }
    assert!(
        std::path::Path::new(&flag_db).exists(),
        "--db file not created"
    );
    assert!(
        !std::path::Path::new(&path("config.sqlite")).exists(),
        "the config file's database was opened despite --db"
    );
    assert!(
        lines.iter().all(|line| !line.contains("config.")),
        "a config path leaked past its flag:\n{}",
        lines.join("\n")
    );
}
