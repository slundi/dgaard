//! Batch-mode integration test.
//!
//! Spins up a local UDP DNS mock that responds to any A-record query with a
//! canned answer, invokes the digaard binary reading domains from stdin, and
//! asserts one JSON object per input line — in the same order.

use std::net::Ipv4Addr;
use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::net::UdpSocket;

fn build_answer(query: &Message) -> Message {
    let mut resp = Message::query();
    resp.metadata.id = query.metadata.id;
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.response_code = ResponseCode::NoError;
    resp.metadata.recursion_available = true;

    // Echo back the question we received, then attach an A record.
    if let Some(q) = query.queries.first() {
        resp.add_query(q.clone());
        let synthetic = Record::from_rdata(
            q.name().clone(),
            60,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 42))),
        );
        resp.add_answer(synthetic);
    }
    resp
}

async fn spawn_mock() -> (u16, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let resp = build_answer(&query);
            let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    (port, handle)
}

#[tokio::test]
async fn stdin_ndjson_preserves_input_order() {
    let (port, mock) = spawn_mock().await;

    // Give the mock a moment to be ready (bind is complete, but tokio runtime
    // needs to schedule the task).
    tokio::task::yield_now().await;

    let domains: Vec<&str> = vec![
        "alpha.test.",
        "bravo.test.",
        "charlie.test.",
        "delta.test.",
        "echo.test.",
    ];
    let stdin_text = domains.iter().map(|s| format!("{s}\n")).collect::<String>();

    let bin = env!("CARGO_BIN_EXE_digaard");
    let mut child = Command::new(bin)
        .args([
            "-f",
            "-",
            "-s",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--json",
            "--timeout",
            "500",
            "-j",
            "4",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn digaard");

    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(stdin_text.as_bytes()).await.unwrap();
        // Dropping closes stdin so the child sees EOF.
    }

    let output = child.wait_with_output().await.expect("wait digaard");
    assert!(
        output.status.success(),
        "digaard exited with {:?}, stderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        domains.len(),
        "expected one JSON object per domain, got:\n{stdout}"
    );

    for (line, expected) in lines.iter().zip(&domains) {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid json line");
        assert_eq!(v["query"].as_str().unwrap(), *expected, "order preserved");
        assert_eq!(v["status"].as_str().unwrap(), "No Error");
        let answers = v["answer"].as_array().unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0]["data"].as_str().unwrap(), "198.51.100.42");
    }

    mock.abort();
    let _ = mock.await;
}

#[tokio::test]
async fn positional_multi_domain_text_batch() {
    let (port, mock) = spawn_mock().await;
    tokio::task::yield_now().await;

    let bin = env!("CARGO_BIN_EXE_digaard");
    let output = Command::new(bin)
        .args([
            "one.test.",
            "two.test.",
            "three.test.",
            "-s",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--color",
            "never",
            "--timeout",
            "500",
        ])
        .output()
        .await
        .expect("run digaard");

    assert!(
        output.status.success(),
        "digaard exited with {:?}, stderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    // The batch header should appear for each input in order.
    let one = stdout.find(";; ==> one.test. <==").expect("one header");
    let two = stdout.find(";; ==> two.test. <==").expect("two header");
    let three = stdout.find(";; ==> three.test. <==").expect("three header");
    assert!(one < two && two < three, "batch headers in input order");

    // Answers should mention the synthetic IP.
    assert!(stdout.contains("198.51.100.42"), "answer ip present");

    // Assert this is text (dig-style), not JSON, and has no leftover ANSI.
    assert!(stdout.contains(";; ->>HEADER<<-"));
    assert!(
        !stdout.contains("\x1b["),
        "no ANSI escapes when --color never"
    );

    mock.abort();
    let _ = mock.await;
}

#[tokio::test]
async fn empty_input_is_an_error() {
    let bin = env!("CARGO_BIN_EXE_digaard");
    let mut child = Command::new(bin)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn digaard");
    // Close stdin immediately with no data.
    drop(child.stdin.take());

    let output = child.wait_with_output().await.expect("wait");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("no domain names"),
        "expected 'no domain names' in stderr, got:\n{stderr}"
    );
}
