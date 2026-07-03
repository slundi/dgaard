//! End-to-end DoQ round-trip against a locally-hosted quinn server.
//!
//! Verifies:
//!   - ALPN "doq" negotiation
//!   - RFC 9250 §4.2.1 message ID = 0 on the wire
//!   - Bidirectional stream framing (2-byte length prefix + DNS message)
//!   - The response we send is decoded on the client side

use std::net::Ipv4Addr;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig};

use digaard::transport::{TlsSettings, TransportConfig, TransportKind, send};

fn init_crypto_provider() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

fn self_signed_server_config() -> (ServerConfig, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"doq".to_vec()];

    let quic_server: QuicServerConfig = server_crypto.try_into().unwrap();
    let server_config = ServerConfig::with_crypto(Arc::new(quic_server));
    (server_config, cert_der.to_vec())
}

async fn spawn_doq_server() -> u16 {
    let (server_cfg, _cert_der) = self_signed_server_config();
    let endpoint = Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let port = endpoint.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    // Read length prefix
                    let mut len_buf = [0u8; 2];
                    if recv.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let qlen = u16::from_be_bytes(len_buf) as usize;
                    let mut qbuf = vec![0u8; qlen];
                    if recv.read_exact(&mut qbuf).await.is_err() {
                        return;
                    }
                    let query = Message::from_bytes(&qbuf).unwrap();
                    // RFC 9250 §4.2.1: message ID MUST be 0 on the wire.
                    assert_eq!(query.metadata.id, 0, "DoQ ID must be zero");

                    // Craft a response and echo it back.
                    let mut resp = Message::query();
                    resp.metadata.id = query.metadata.id; // 0
                    resp.metadata.message_type = MessageType::Response;
                    resp.metadata.response_code = ResponseCode::NoError;
                    if let Some(q) = query.queries.first() {
                        resp.add_query(q.clone());
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::A(A(Ipv4Addr::new(203, 0, 113, 42))),
                        ));
                    }
                    let wire = resp.to_vec().unwrap();
                    let len = (wire.len() as u16).to_be_bytes();
                    let _ = send.write_all(&len).await;
                    let _ = send.write_all(&wire).await;
                    let _ = send.finish();
                    // Keep the send-side alive until the client closes.
                    let _ = conn.closed().await;
                }
            });
        }
    });
    port
}

fn build_query(name: &str, qtype: RecordType) -> Message {
    let mut msg = Message::query();
    // Non-zero ID; DoQ transport should rewrite to 0 before wire send.
    msg.metadata.id = 0x1234;
    msg.metadata.recursion_desired = true;
    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).unwrap());
    q.set_query_type(qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg
}

#[tokio::test]
async fn doq_roundtrip_over_self_signed_quic() {
    init_crypto_provider();
    let port = spawn_doq_server().await;

    let cfg = TransportConfig {
        server: "127.0.0.1".to_string(),
        port,
        timeout_ms: 3_000,
        tls: TlsSettings {
            servername: Some("localhost".to_string()),
            insecure: true,
            ..TlsSettings::default()
        },
        ..TransportConfig::default()
    };

    let query = build_query("doq.test.", RecordType::A);
    let resp = send(TransportKind::Quic, &cfg, &query)
        .await
        .expect("DoQ exchange");
    assert_eq!(resp.answers.len(), 1, "expected one A record");
    assert_eq!(
        resp.answers[0].data.to_string(),
        Ipv4Addr::new(203, 0, 113, 42).to_string(),
    );
}
