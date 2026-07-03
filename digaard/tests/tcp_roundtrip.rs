//! TCP transport integration tests.

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use digaard::transport::{TransportConfig, tcp};

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
    resp.metadata.recursion_available = true;

    for q in &query.queries {
        resp.add_query(q.clone());
    }
    let q = &query.queries[0];
    resp.add_answer(Record::from_rdata(q.name().clone(), ttl, RData::A(A(ip))));
    resp
}

fn config_for(port: u16) -> TransportConfig {
    TransportConfig {
        server: "127.0.0.1".to_string(),
        port,
        timeout_ms: 1_000,
        retry: 0,
        ipv4_only: false,
        ipv6_only: false,
    }
}

#[tokio::test]
async fn tcp_length_prefixed_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();

        // Read 2-byte length prefix, then that many bytes.
        let mut lenbuf = [0u8; 2];
        sock.read_exact(&mut lenbuf).await.unwrap();
        let qlen = u16::from_be_bytes(lenbuf) as usize;
        let mut qbuf = vec![0u8; qlen];
        sock.read_exact(&mut qbuf).await.unwrap();

        let query = Message::from_bytes(&qbuf).unwrap();
        assert_eq!(query.queries.len(), 1);
        assert_eq!(query.queries[0].name().to_ascii(), "tcp.example.");
        assert_eq!(query.queries[0].query_type(), RecordType::A);

        // Write length-prefixed response.
        let resp = canned_response(&query, Ipv4Addr::new(203, 0, 113, 7), 60);
        let wire = resp.to_vec().unwrap();
        let len = (wire.len() as u16).to_be_bytes();
        sock.write_all(&len).await.unwrap();
        sock.write_all(&wire).await.unwrap();
        sock.flush().await.unwrap();
    });

    let query = build_query("tcp.example.", RecordType::A);
    let cfg = config_for(addr.port());
    let response = tcp::send(&cfg, &query).await.expect("tcp exchange");
    assert_eq!(response.answers.len(), 1);
    assert_eq!(
        response.answers[0].data.to_string(),
        Ipv4Addr::new(203, 0, 113, 7).to_string()
    );

    handle.await.unwrap();
}
