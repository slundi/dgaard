//! UDP transport integration tests.
//!
//! Each test spins up a local `tokio::net::UdpSocket` that pretends to be a
//! resolver, so we can assert both the wire format of the outgoing query and
//! the parsing of a canned response.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::net::UdpSocket;

use digaard::error::Error;
use digaard::transport::{TransportConfig, udp};

fn build_query(name: &str, qtype: RecordType) -> Message {
    let mut msg = Message::query();
    msg.metadata.recursion_desired = true;

    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).unwrap());
    q.set_query_type(qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg
}

fn canned_response(query: &Message, ip: Ipv4Addr, ttl: u32) -> Message {
    let mut resp = Message::query();
    resp.metadata.id = query.metadata.id;
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.response_code = ResponseCode::NoError;
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;

    for q in &query.queries {
        resp.add_query(q.clone());
    }

    let q = &query.queries[0];
    resp.add_answer(Record::from_rdata(q.name().clone(), ttl, RData::A(A(ip))));
    resp
}

async fn bind_local() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind mock server")
}

fn config_for(port: u16, timeout_ms: u64, retry: u32) -> TransportConfig {
    TransportConfig {
        server: "127.0.0.1".to_string(),
        port,
        timeout_ms,
        retry,
        ipv4_only: false,
        ipv6_only: false,
    }
}

#[tokio::test]
async fn udp_roundtrip_success() {
    let server = bind_local().await;
    let server_addr = server.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = server.recv_from(&mut buf).await.unwrap();
        let query = Message::from_bytes(&buf[..n]).expect("valid query");

        assert_eq!(query.queries.len(), 1, "one question expected");
        let q = &query.queries[0];
        assert_eq!(q.name().to_ascii(), "example.com.");
        assert_eq!(q.query_type(), RecordType::A);
        assert!(query.metadata.recursion_desired);

        let resp = canned_response(&query, Ipv4Addr::new(93, 184, 216, 34), 300);
        let wire = resp.to_vec().unwrap();
        server.send_to(&wire, peer).await.unwrap();
    });

    let query = build_query("example.com.", RecordType::A);
    let cfg = config_for(server_addr.port(), 1_000, 0);
    let response = udp::send(&cfg, &query).await.expect("udp exchange");

    assert_eq!(response.metadata.id, query.metadata.id);
    assert_eq!(response.answers.len(), 1);
    let rr = &response.answers[0];
    assert_eq!(rr.name, Name::from_str("example.com.").unwrap());
    assert_eq!(rr.record_type(), RecordType::A);

    handle.await.unwrap();
}

#[tokio::test]
async fn udp_retries_on_timeout_then_succeeds() {
    let server = bind_local().await;
    let server_addr = server.local_addr().unwrap();

    let received = Arc::new(AtomicU32::new(0));
    let received_srv = Arc::clone(&received);

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let attempt = received_srv.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt < 2 {
                // Drop the first packet on the floor to force a client-side timeout.
                continue;
            }
            let query = Message::from_bytes(&buf[..n]).unwrap();
            let resp = canned_response(&query, Ipv4Addr::new(10, 0, 0, 1), 60);
            server.send_to(&resp.to_vec().unwrap(), peer).await.unwrap();
            break;
        }
    });

    let query = build_query("retry.test.", RecordType::A);
    let cfg = config_for(server_addr.port(), 100, 2);
    let response = udp::send(&cfg, &query).await.expect("udp exchange");
    assert_eq!(response.answers.len(), 1);
    assert!(
        received.load(Ordering::SeqCst) >= 2,
        "retry should have been attempted"
    );

    handle.await.unwrap();
}

#[tokio::test]
async fn udp_gives_up_after_exhausting_retries() {
    let server = bind_local().await;
    let server_addr = server.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        // Silently drain — never reply.
        let mut buf = vec![0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                if server.recv_from(&mut buf).await.is_err() {
                    break;
                }
            }
        })
        .await;
    });

    let query = build_query("blackhole.test.", RecordType::A);
    let cfg = config_for(server_addr.port(), 50, 1);
    let err = udp::send(&cfg, &query).await.unwrap_err();
    assert!(
        matches!(err, Error::Timeout),
        "expected Timeout, got {err:?}"
    );

    handle.abort();
    let _ = handle.await;
}

#[tokio::test]
async fn udp_reports_truncated_when_tc_set() {
    let server = bind_local().await;
    let server_addr = server.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = server.recv_from(&mut buf).await.unwrap();
        let query = Message::from_bytes(&buf[..n]).unwrap();

        let mut resp = canned_response(&query, Ipv4Addr::new(1, 2, 3, 4), 30);
        resp.metadata.truncation = true;
        server.send_to(&resp.to_vec().unwrap(), peer).await.unwrap();
    });

    let query = build_query("big.test.", RecordType::A);
    let cfg = config_for(server_addr.port(), 500, 0);
    let err = udp::send(&cfg, &query).await.unwrap_err();
    assert!(
        matches!(err, Error::Truncated),
        "expected Truncated, got {err:?}"
    );

    handle.await.unwrap();
}
