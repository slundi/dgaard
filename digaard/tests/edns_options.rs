//! End-to-end verification that EDNS options make it onto the wire.

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::net::UdpSocket;

use digaard::cli::EdnsOpts;
use digaard::query::{QueryFlags, build_query, pad_message};
use digaard::transport::{TransportConfig, udp};

fn base_flags() -> QueryFlags {
    QueryFlags {
        recursion_desired: true,
        authoritative: false,
        authentic_data: false,
        checking_disabled: false,
        dnssec_ok: false,
    }
}

fn edns_all_off() -> EdnsOpts {
    EdnsOpts {
        enabled: true,
        bufsize: None,
        subnet: None,
        nsid: false,
        cookie: None,
        pad: None,
    }
}

fn canned_ack(query: &Message) -> Message {
    let mut resp = Message::query();
    resp.metadata.id = query.metadata.id;
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.response_code = ResponseCode::NoError;
    for q in &query.queries {
        resp.add_query(q.clone());
    }
    if let Some(q) = query.queries.first() {
        resp.add_answer(Record::from_rdata(
            q.name().clone(),
            60,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 1))),
        ));
    }
    resp
}

async fn spawn_mock() -> (u16, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
        let received = buf[..n].to_vec();
        let query = Message::from_bytes(&received).unwrap();
        let resp = canned_ack(&query);
        let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
        let _ = tx.send(received);
    });
    (port, rx)
}

fn cfg_for(port: u16) -> TransportConfig {
    TransportConfig {
        server: "127.0.0.1".to_string(),
        port,
        timeout_ms: 500,
        retry: 0,
        ipv4_only: false,
        ipv6_only: false,
    }
}

fn build(name: &str, edns: EdnsOpts, pad: Option<u16>) -> Message {
    let n = Name::from_ascii(name).unwrap();
    let mut q = build_query(&n, RecordType::A, DNSClass::IN, base_flags(), &edns).unwrap();
    if let Some(block) = pad {
        pad_message(&mut q, block).unwrap();
    }
    q
}

#[tokio::test]
async fn subnet_and_nsid_reach_the_wire() {
    let (port, rx) = spawn_mock().await;

    let edns = EdnsOpts {
        subnet: Some("192.0.2.0/24".to_string()),
        nsid: true,
        bufsize: Some(1232),
        ..edns_all_off()
    };
    let query = build("edns.test.", edns, None);
    let _ = udp::send(&cfg_for(port), &query).await.unwrap();
    let sent_bytes = rx.await.unwrap();

    let sent = Message::from_bytes(&sent_bytes).unwrap();
    let edns_in = sent.edns.expect("EDNS present");
    assert!(edns_in.options().get(EdnsCode::Subnet).is_some());
    assert!(edns_in.options().get(EdnsCode::NSID).is_some());
}

#[tokio::test]
async fn cookie_reaches_the_wire() {
    let (port, rx) = spawn_mock().await;

    let cookie_bytes = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
    let edns = EdnsOpts {
        cookie: Some(cookie_bytes.clone()),
        ..edns_all_off()
    };
    let query = build("cookie.test.", edns, None);
    let _ = udp::send(&cfg_for(port), &query).await.unwrap();
    let sent_bytes = rx.await.unwrap();

    let sent = Message::from_bytes(&sent_bytes).unwrap();
    let opt = sent
        .edns
        .as_ref()
        .unwrap()
        .options()
        .get(EdnsCode::Cookie)
        .expect("Cookie present");
    match opt {
        EdnsOption::Unknown(_, data) => assert_eq!(data, &cookie_bytes),
        other => panic!("expected Cookie as Unknown, got {other:?}"),
    }
}

#[tokio::test]
async fn padding_rounds_wire_up_to_block() {
    let (port, rx) = spawn_mock().await;

    let edns = EdnsOpts {
        pad: Some(128),
        ..edns_all_off()
    };
    let query = build("pad.test.", edns, Some(128));
    let _ = udp::send(&cfg_for(port), &query).await.unwrap();
    let sent_bytes = rx.await.unwrap();

    assert!(!sent_bytes.is_empty());
    assert_eq!(
        sent_bytes.len() % 128,
        0,
        "wire len {} not a multiple of 128",
        sent_bytes.len()
    );
}

#[tokio::test]
async fn no_edns_produces_no_opt_record() {
    let (port, rx) = spawn_mock().await;

    let edns = EdnsOpts {
        enabled: false,
        ..edns_all_off()
    };
    let query = build("plain.test.", edns, None);
    let _ = udp::send(&cfg_for(port), &query).await.unwrap();
    let sent_bytes = rx.await.unwrap();

    let sent = Message::from_bytes(&sent_bytes).unwrap();
    assert!(sent.edns.is_none(), "expected no OPT record");
}
