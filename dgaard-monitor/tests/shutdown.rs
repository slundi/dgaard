//! End-to-end check of the shutdown sequence on SIGTERM: the process must
//! finish cleanly well within the 10 s `docker stop` grace period.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
/// `docker stop` sends SIGKILL after 10 s.
const DOCKER_GRACE_PERIOD: Duration = Duration::from_secs(10);

#[test]
fn sigterm_shuts_down_cleanly_within_the_grace_period() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).to_str().unwrap().to_string();
    let config_path = path("monitor.toml");
    std::fs::write(
        &config_path,
        format!(
            "[input]\nsocket = \"{}\"\nindex = \"{}\"\n\n[persistence]\ndb = \"{}\"\n",
            path("stats.sock"),
            path("hosts.bin"),
            path("stats.sqlite"),
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_dgaard-monitor"))
        .args(["--headless", "-c", &config_path])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let (line_tx, line_rx) = mpsc::channel();
    let stderr = child.stderr.take().unwrap();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = line_tx.send(line);
        }
    });

    // Every task is up once the database is open and the socket reader runs.
    let mut lines = Vec::new();
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while !lines
        .iter()
        .any(|line: &String| line.contains("retrying in"))
    {
        match line_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => lines.push(line),
            Err(_) => {
                let _ = child.kill();
                panic!("monitor never started:\n{}", lines.join("\n"));
            }
        }
    }

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());

    let signalled_at = Instant::now();
    let exit = loop {
        if let Some(exit) = child.try_wait().unwrap() {
            break exit;
        }
        if signalled_at.elapsed() > DOCKER_GRACE_PERIOD {
            let _ = child.kill();
            panic!("still running {DOCKER_GRACE_PERIOD:?} after SIGTERM");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let took = signalled_at.elapsed();
    reader.join().unwrap();
    lines.extend(line_rx.try_iter());
    let stderr = lines.join("\n");

    assert!(exit.success(), "exit status {exit:?}\n{stderr}");
    assert!(
        stderr.contains("Received SIGTERM, shutting down..."),
        "{stderr}"
    );
    assert!(stderr.contains("All tasks stopped. Bye."), "{stderr}");
    assert!(
        !stderr.contains("aborted"),
        "a task had to be aborted:\n{stderr}"
    );
    assert!(took < Duration::from_secs(2), "shutdown took {took:?}");
}
