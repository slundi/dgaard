//! End-to-end tests for `--validate` and `--stats` from M6.

use std::net::Ipv4Addr;
use std::process::Stdio;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::net::UdpSocket;
use tokio::process::Command;

/// Spawn a mock UDP DNS server that echoes A records for every query.
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
            let mut resp = Message::query();
            resp.metadata.id = query.metadata.id;
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NoError;
            resp.metadata.authentic_data = true; // simulate validating resolver
            if let Some(q) = query.queries.first() {
                resp.add_query(q.clone());
                resp.add_answer(Record::from_rdata(
                    q.name().clone(),
                    60,
                    RData::A(A(Ipv4Addr::new(203, 0, 113, 9))),
                ));
            }
            let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    (port, handle)
}

#[tokio::test]
async fn validate_reports_secure_when_ad_bit_is_set() {
    let (port, mock) = spawn_mock().await;
    tokio::task::yield_now().await;

    let bin = env!("CARGO_BIN_EXE_digaard");
    let out = Command::new(bin)
        .args([
            "secure.test",
            "-s",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--validate",
            "--color",
            "never",
            "--timeout",
            "500",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run digaard");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains(";; DNSSEC: SECURE"),
        "expected DNSSEC verdict in output:\n{stdout}"
    );

    mock.abort();
    let _ = mock.await;
}

#[tokio::test]
async fn validate_json_includes_dnssec_object() {
    let (port, mock) = spawn_mock().await;
    tokio::task::yield_now().await;

    let bin = env!("CARGO_BIN_EXE_digaard");
    let out = Command::new(bin)
        .args([
            "secure.test",
            "-s",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--validate",
            "--json",
            "--timeout",
            "500",
        ])
        .output()
        .await
        .expect("run digaard");
    assert!(out.status.success());

    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["dnssec"]["status"].as_str().unwrap(), "SECURE");

    mock.abort();
    let _ = mock.await;
}

#[tokio::test]
async fn stats_summary_printed_after_batch() {
    let (port, mock) = spawn_mock().await;
    tokio::task::yield_now().await;

    let bin = env!("CARGO_BIN_EXE_digaard");
    let out = Command::new(bin)
        .args([
            "a.test",
            "b.test",
            "c.test",
            "-s",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--stats",
            "--short",
            "--color",
            "never",
            "--timeout",
            "500",
        ])
        .output()
        .await
        .expect("run digaard");
    assert!(out.status.success());

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains(";; --- stats ---"),
        "no summary in:\n{stderr}"
    );
    assert!(stderr.contains("queries: 3"));
    assert!(stderr.contains("errors: 0"));
    assert!(stderr.contains("min="));
    assert!(stderr.contains("p95="));

    mock.abort();
    let _ = mock.await;
}
