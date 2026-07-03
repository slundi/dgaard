//! Integration tests for M3 surface — reverse queries, IDN, and EDGE decoding.

use std::net::Ipv4Addr;
use std::process::Stdio;

use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{A, name::PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::net::UdpSocket;
use tokio::process::Command;

async fn spawn_mock<F>(handler: F) -> u16
where
    F: FnOnce(Message) -> Message + Send + 'static,
{
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
        let query = Message::from_bytes(&buf[..n]).unwrap();
        let resp = handler(query);
        let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
    });
    port
}

#[tokio::test]
async fn reverse_ipv4_hits_in_addr_arpa() {
    let port = spawn_mock(|query| {
        // Assert we got a PTR query for 8.8.4.4.in-addr.arpa
        assert_eq!(query.queries.len(), 1);
        let q = &query.queries[0];
        assert_eq!(q.query_type(), RecordType::PTR);
        assert_eq!(q.name().to_ascii(), "4.4.8.8.in-addr.arpa.");

        let mut resp = Message::query();
        resp.metadata.id = query.metadata.id;
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.response_code = ResponseCode::NoError;
        resp.add_query(q.clone());
        resp.add_answer(Record::from_rdata(
            q.name().clone(),
            300,
            RData::PTR(PTR(Name::from_ascii("dns.google.").unwrap())),
        ));
        resp
    })
    .await;

    let bin = env!("CARGO_BIN_EXE_digaard");
    let out = Command::new(bin)
        .args([
            "-x",
            "8.8.4.4",
            "-s",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--short",
            "--timeout",
            "500",
        ])
        .output()
        .await
        .expect("run digaard");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("dns.google."), "got: {stdout}");
}

#[tokio::test]
async fn idn_input_encodes_as_punycode() {
    let port = spawn_mock(|query| {
        let q = &query.queries[0];
        assert_eq!(q.name().to_ascii(), "xn--bcher-kva.de.");

        let mut resp = Message::query();
        resp.metadata.id = query.metadata.id;
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.response_code = ResponseCode::NoError;
        resp.add_query(q.clone());
        resp.add_answer(Record::from_rdata(
            q.name().clone(),
            60,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 5))),
        ));
        resp
    })
    .await;

    let bin = env!("CARGO_BIN_EXE_digaard");
    let out = Command::new(bin)
        .args([
            "bücher.de",
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
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("xn--bcher-kva.de."),
        "punycode in wire form"
    );
    // Unicode hint comment should follow.
    assert!(stdout.contains("(bücher.de.)"), "unicode hint present");
}

#[tokio::test]
async fn edge_flag_decodes_extended_dns_error() {
    // Build a response with an EDGE (Extended DNS Error) code 15 = "Blocked"
    // and text "policy: adblock".
    let port = spawn_mock(|query| {
        let q = &query.queries[0];

        let mut resp = Message::query();
        resp.metadata.id = query.metadata.id;
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.response_code = ResponseCode::NoError;
        resp.add_query(q.clone());

        // Attach EDNS with EDGE option (code 15).
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        let mut payload = Vec::new();
        payload.extend_from_slice(&15u16.to_be_bytes()); // EDGE info code
        payload.extend_from_slice(b"policy: adblock");
        let edge_code: u16 = EdnsCode::from(15u16).into();
        edns.options_mut()
            .insert(EdnsOption::Unknown(edge_code, payload));
        resp.set_edns(edns);

        resp
    })
    .await;

    let bin = env!("CARGO_BIN_EXE_digaard");
    let out = Command::new(bin)
        .args([
            "blocked.test",
            "-s",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--edge",
            "--color",
            "never",
            "--timeout",
            "500",
        ])
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
        stdout.contains(";; EDGE"),
        "EDGE section header present in:\n{stdout}"
    );
    assert!(stdout.contains("Blocked"), "purpose label");
    assert!(stdout.contains("code 15"));
    assert!(stdout.contains("policy: adblock"), "extra-text present");
}

#[tokio::test]
async fn hex_flag_dumps_wire_bytes() {
    let port = spawn_mock(|query| {
        let q = &query.queries[0];
        let mut resp = Message::query();
        resp.metadata.id = query.metadata.id;
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.response_code = ResponseCode::NoError;
        resp.add_query(q.clone());
        resp.add_answer(Record::from_rdata(
            q.name().clone(),
            60,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 7))),
        ));
        resp
    })
    .await;

    let bin = env!("CARGO_BIN_EXE_digaard");
    let out = Command::new(bin)
        .args([
            "hex.test",
            "-s",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--hex",
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
    assert!(stdout.contains(";; wire dump"));
    assert!(stdout.contains("00000000  "), "offset column present");
}
