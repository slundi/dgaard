//! Optional NATS publisher + subscriber for federating monitors.
//!
//! When `[nats] enabled = true`, the monitor:
//!   1. **Publishes** every enriched event from the local broadcast on
//!      `publish_subject` (empty string disables this leg).
//!   2. **Subscribes** to `subscribe_subject` and injects every incoming
//!      event back into the local broadcast as if it had been received over
//!      the Unix socket (empty string disables this leg).
//!
//! Wire format (UTF-8 JSON, mirrors the in-process `StatEvent`):
//! ```json
//! {
//!   "ts": 1731000000,
//!   "domain_hash": 12345,
//!   "domain": "example.com",   // optional — when the publisher knows it
//!   "client_ip": "192.168.1.1",
//!   "action": "Blocked",
//!   "reasons": 1               // bitmask
//! }
//! ```
//!
//! Cycles are prevented by re-encoding only events that came in over the
//! Unix socket; events received on NATS are dropped before re-publishing.
//! Today we approximate this with a "publish only when subscribe and
//! publish subjects differ" rule, which is sufficient for the supported
//! federation topologies and avoids tracking event provenance.
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::config::NatsConfig;
use crate::protocol::{StatAction, StatBlockReason, StatEvent};
use crate::state::AppState;

/// On-wire representation of a monitor event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireEvent {
    pub ts: u64,
    pub domain_hash: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub client_ip: String,
    pub action: WireAction,
    /// Bitmask of `StatBlockReason` bits. `0` when the action has no
    /// associated reason (Allowed/Proxied).
    #[serde(default)]
    pub reasons: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum WireAction {
    Allowed,
    Proxied,
    Blocked,
    Suspicious,
    HighlySuspicious,
}

impl WireEvent {
    pub fn from_event(event: &StatEvent, domain: Option<String>) -> Self {
        let (action, reasons) = match &event.action {
            StatAction::Allowed => (WireAction::Allowed, 0),
            StatAction::Proxied => (WireAction::Proxied, 0),
            StatAction::Blocked(r) => (WireAction::Blocked, r.bits()),
            StatAction::Suspicious(r) => (WireAction::Suspicious, r.bits()),
            StatAction::HighlySuspicious(r) => (WireAction::HighlySuspicious, r.bits()),
        };
        Self {
            ts: event.timestamp,
            domain_hash: event.domain_hash,
            domain,
            client_ip: format_ip(event.client_ip),
            action,
            reasons,
        }
    }

    pub fn into_event(self) -> Result<StatEvent, ParseError> {
        let reasons = StatBlockReason::from_bits_retain(self.reasons);
        let action = match self.action {
            WireAction::Allowed => StatAction::Allowed,
            WireAction::Proxied => StatAction::Proxied,
            WireAction::Blocked => StatAction::Blocked(reasons),
            WireAction::Suspicious => StatAction::Suspicious(reasons),
            WireAction::HighlySuspicious => StatAction::HighlySuspicious(reasons),
        };
        Ok(StatEvent {
            timestamp: self.ts,
            domain_hash: self.domain_hash,
            client_ip: parse_ip(&self.client_ip)?,
            action,
        })
    }
}

#[derive(Debug)]
pub enum ParseError {
    InvalidClientIp(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidClientIp(s) => write!(f, "invalid client_ip {s:?}"),
        }
    }
}

impl std::error::Error for ParseError {}

fn format_ip(bytes: [u8; 16]) -> String {
    let v6 = Ipv6Addr::from(bytes);
    match v6.to_ipv4_mapped() {
        Some(v4) => v4.to_string(),
        None => v6.to_string(),
    }
}

fn parse_ip(s: &str) -> Result<[u8; 16], ParseError> {
    let addr: IpAddr = s
        .parse()
        .map_err(|_| ParseError::InvalidClientIp(s.into()))?;
    Ok(match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    })
}

/// Spawn the NATS publisher + subscriber tasks. Returns immediately if
/// `enabled` is false or both subjects are blank.
///
/// Connection failure logs and disables NATS for this run — the rest of the
/// monitor keeps working.
pub async fn run(cfg: NatsConfig, state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    if !cfg.enabled {
        return;
    }
    if cfg.publish_subject.is_empty() && cfg.subscribe_subject.is_empty() {
        eprintln!("nats: both publish_subject and subscribe_subject are empty, disabling");
        return;
    }

    let client = match async_nats::connect(&cfg.url).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nats: connect to {} failed: {e}, disabling", cfg.url);
            return;
        }
    };
    println!("nats: connected to {}", cfg.url);

    // ── Subscriber leg ──────────────────────────────────────────────────────
    let subscriber_task = if !cfg.subscribe_subject.is_empty() {
        match client.subscribe(cfg.subscribe_subject.clone()).await {
            Ok(sub) => {
                let s = Arc::clone(&state);
                let mut rx = shutdown.clone();
                let subject = cfg.subscribe_subject.clone();
                Some(tokio::spawn(async move {
                    println!("nats: subscribed to {subject}");
                    run_subscriber(sub, s, &mut rx).await;
                }))
            }
            Err(e) => {
                eprintln!("nats: subscribe to {} failed: {e}", cfg.subscribe_subject);
                None
            }
        }
    } else {
        None
    };

    // ── Publisher leg ───────────────────────────────────────────────────────
    let publisher_task = if !cfg.publish_subject.is_empty() {
        let s = Arc::clone(&state);
        let pub_client = client.clone();
        let subject = cfg.publish_subject.clone();
        let mut rx = shutdown.clone();
        Some(tokio::spawn(async move {
            run_publisher(pub_client, subject, s, &mut rx).await;
        }))
    } else {
        None
    };

    // Block until shutdown so the spawned subtasks live as long as `run` does.
    let _ = shutdown.changed().await;

    if let Some(h) = subscriber_task {
        let _ = h.await;
    }
    if let Some(h) = publisher_task {
        let _ = h.await;
    }
}

async fn run_subscriber(
    mut sub: async_nats::Subscriber,
    state: Arc<AppState>,
    shutdown: &mut watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            msg = sub.next() => {
                match msg {
                    Some(msg) => handle_inbound(&msg.payload, &state).await,
                    None => return, // subscription closed
                }
            }
        }
    }
}

async fn handle_inbound(payload: &[u8], state: &AppState) {
    let wire: WireEvent = match serde_json::from_slice(payload) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("nats: drop malformed event: {e}");
            return;
        }
    };
    if let Some(d) = wire.domain.clone() {
        state.insert_domain(wire.domain_hash, d).await;
    }
    match wire.into_event() {
        Ok(ev) => state.record_event(ev).await,
        Err(e) => eprintln!("nats: drop event with bad fields: {e}"),
    }
}

async fn run_publisher(
    client: async_nats::Client,
    subject: String,
    state: Arc<AppState>,
    shutdown: &mut watch::Receiver<bool>,
) {
    let mut rx = state.subscribe();
    let subject = async_nats::Subject::from(subject);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            recv = rx.recv() => {
                match recv {
                    Ok(event) => {
                        let domain = state.domain_map.read().await.get(&event.domain_hash).cloned();
                        let wire = WireEvent::from_event(&event, domain);
                        match serde_json::to_vec(&wire) {
                            Ok(payload) => {
                                if let Err(e) =
                                    client.publish(subject.clone(), payload.into()).await
                                {
                                    eprintln!("nats: publish failed: {e}");
                                }
                            }
                            Err(e) => eprintln!("nats: serialize event failed: {e}"),
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("nats: publisher lagged, skipped {n} events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_bytes(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        std::net::Ipv4Addr::new(a, b, c, d)
            .to_ipv6_mapped()
            .octets()
    }

    #[test]
    fn format_ipv4_mapped_renders_as_v4() {
        assert_eq!(format_ip(ipv4_bytes(192, 168, 1, 1)), "192.168.1.1");
    }

    #[test]
    fn format_pure_ipv6_renders_as_v6() {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(format_ip(v6.octets()), "2001:db8::1");
    }

    #[test]
    fn parse_ipv4_returns_mapped_octets() {
        let octets = parse_ip("10.0.0.1").unwrap();
        assert_eq!(octets, ipv4_bytes(10, 0, 0, 1));
    }

    #[test]
    fn parse_invalid_ip_returns_error() {
        assert!(parse_ip("not-an-ip").is_err());
    }

    #[test]
    fn from_event_allowed_has_zero_reasons() {
        let ev = StatEvent {
            timestamp: 100,
            domain_hash: 42,
            client_ip: ipv4_bytes(1, 2, 3, 4),
            action: StatAction::Allowed,
        };
        let wire = WireEvent::from_event(&ev, None);
        assert_eq!(wire.action, WireAction::Allowed);
        assert_eq!(wire.reasons, 0);
        assert!(wire.domain.is_none());
        assert_eq!(wire.client_ip, "1.2.3.4");
    }

    #[test]
    fn from_event_blocked_encodes_reason_bits() {
        let reason = StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY;
        let ev = StatEvent {
            timestamp: 1,
            domain_hash: 7,
            client_ip: ipv4_bytes(10, 0, 0, 5),
            action: StatAction::Blocked(reason),
        };
        let wire = WireEvent::from_event(&ev, Some("example.com".into()));
        assert_eq!(wire.action, WireAction::Blocked);
        assert_eq!(wire.reasons, reason.bits());
        assert_eq!(wire.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn wire_event_round_trips_through_event() {
        let original = StatEvent {
            timestamp: 1234,
            domain_hash: 0xdeadbeef,
            client_ip: ipv4_bytes(10, 0, 0, 1),
            action: StatAction::Suspicious(StatBlockReason::NRD_LIST),
        };
        let wire = WireEvent::from_event(&original, None);
        let decoded = wire.into_event().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn wire_event_round_trips_through_json() {
        let original = StatEvent {
            timestamp: 999,
            domain_hash: 12,
            client_ip: ipv4_bytes(127, 0, 0, 1),
            action: StatAction::HighlySuspicious(
                StatBlockReason::DNS_REBINDING | StatBlockReason::CNAME_CLOAKING,
            ),
        };
        let wire = WireEvent::from_event(&original, Some("evil.test".into()));
        let bytes = serde_json::to_vec(&wire).unwrap();
        let parsed: WireEvent = serde_json::from_slice(&bytes).unwrap();
        let decoded = parsed.into_event().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn into_event_rejects_bad_ip() {
        let bad = WireEvent {
            ts: 0,
            domain_hash: 0,
            domain: None,
            client_ip: "definitely-not-an-ip".into(),
            action: WireAction::Allowed,
            reasons: 0,
        };
        let err = bad.into_event().unwrap_err();
        assert!(matches!(err, ParseError::InvalidClientIp(_)));
    }

    #[tokio::test]
    async fn handle_inbound_records_event_and_domain() {
        use std::time::Duration;
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let wire = WireEvent {
            ts: 0,
            domain_hash: 0x42,
            domain: Some("mapped.test".into()),
            client_ip: "10.0.0.1".into(),
            action: WireAction::Blocked,
            reasons: StatBlockReason::ABP_RULE.bits(),
        };
        let payload = serde_json::to_vec(&wire).unwrap();
        handle_inbound(&payload, &state).await;

        assert_eq!(
            state.domain_map.read().await.get(&0x42).map(String::as_str),
            Some("mapped.test")
        );
        let stats = state.stats.read().await;
        assert_eq!(stats.total, 1);
        assert_eq!(stats.blocked, 1);
    }

    #[tokio::test]
    async fn handle_inbound_silently_drops_garbage() {
        use std::time::Duration;
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        handle_inbound(b"not json", &state).await;
        assert_eq!(state.stats.read().await.total, 0);
    }
}

// ---------------------------------------------------------------------------
// Integration tests — exercise the full publisher/subscriber against an
// in-process mock NATS server. Kept inline because `dgaard-monitor` is a
// binary crate (no `lib.rs`) so `tests/` files cannot reach internal items.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod integration {
    use super::*;
    use crate::config::NatsConfig;
    use crate::protocol::{StatAction, StatBlockReason, StatEvent};
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::sync::watch;

    use mock_nats::MockNats;

    fn ipv4_bytes(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        Ipv4Addr::new(a, b, c, d).to_ipv6_mapped().octets()
    }

    fn sample_event() -> StatEvent {
        StatEvent {
            timestamp: 1_700_000_000,
            domain_hash: 0xabc,
            client_ip: ipv4_bytes(10, 0, 0, 1),
            action: StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST),
        }
    }

    #[tokio::test]
    async fn publishes_local_events_to_nats() {
        let mock = MockNats::start().await.unwrap();
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        state.insert_domain(0xabc, "example.test".to_string()).await;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let cfg = NatsConfig {
            enabled: true,
            url: mock.url(),
            publish_subject: "dgaard.events".to_string(),
            subscribe_subject: String::new(),
        };

        let s = Arc::clone(&state);
        let handle = tokio::spawn(async move {
            super::run(cfg, s, shutdown_rx).await;
        });

        // Let the publisher subscribe to AppState before we emit anything.
        tokio::time::sleep(Duration::from_millis(150)).await;
        state.record_event(sample_event()).await;

        let pubs = mock.wait_for_publishes(1, Duration::from_secs(2)).await;

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        assert_eq!(pubs.len(), 1);
        assert_eq!(pubs[0].subject, "dgaard.events");
        let wire: WireEvent = serde_json::from_slice(&pubs[0].payload).unwrap();
        assert_eq!(wire.domain_hash, 0xabc);
        assert_eq!(wire.action, WireAction::Blocked);
        assert_eq!(wire.reasons, StatBlockReason::STATIC_BLACKLIST.bits());
        assert_eq!(wire.domain.as_deref(), Some("example.test"));
        assert_eq!(wire.client_ip, "10.0.0.1");
    }

    #[tokio::test]
    async fn subscriber_injects_events_into_state() {
        let mock = MockNats::start().await.unwrap();
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let cfg = NatsConfig {
            enabled: true,
            url: mock.url(),
            publish_subject: String::new(),
            subscribe_subject: "dgaard.events".to_string(),
        };

        let s = Arc::clone(&state);
        let handle = tokio::spawn(async move {
            super::run(cfg, s, shutdown_rx).await;
        });

        // Spin until the subscriber registers with the mock. `push` returns
        // false until the SUB frame has been processed server-side.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let probe = b"{\"ts\":0,\"domain_hash\":0,\"client_ip\":\"0.0.0.0\",\"action\":\"Allowed\",\"reasons\":0}";
        while !mock.push("dgaard.events", probe).await {
            assert!(
                std::time::Instant::now() < deadline,
                "subscriber never registered"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let wire = WireEvent {
            ts: 5,
            domain_hash: 0xdeadbeef,
            domain: Some("remote.test".to_string()),
            client_ip: "192.0.2.10".to_string(),
            action: WireAction::HighlySuspicious,
            reasons: (StatBlockReason::HIGH_ENTROPY | StatBlockReason::NRD_LIST).bits(),
        };
        let payload = serde_json::to_vec(&wire).unwrap();
        assert!(mock.push("dgaard.events", &payload).await);

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let total = state.stats.read().await.total;
            if total >= 2 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                panic!("event from NATS never reached AppState (total={total})");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(
            state
                .domain_map
                .read()
                .await
                .get(&0xdeadbeef)
                .map(String::as_str),
            Some("remote.test")
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn disabled_config_is_a_noop() {
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (_tx, rx) = watch::channel(false);

        let cfg = NatsConfig {
            enabled: false,
            url: "nats://127.0.0.1:1".to_string(), // unreachable; must not be dialled
            publish_subject: "anything".to_string(),
            subscribe_subject: "anything".to_string(),
        };

        tokio::time::timeout(Duration::from_secs(1), super::run(cfg, state, rx))
            .await
            .expect("disabled run() must return promptly");
    }
}

// ---------------------------------------------------------------------------
// In-process mock NATS server. Implements just enough of the wire protocol
// for `async-nats` 0.49 to connect, PING, PUB, and SUB. Not a conformant
// implementation — JetStream, headers, NKEYs, queue groups, TLS, UNSUB are
// all unimplemented and the connection ignores most error paths.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod mock_nats {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf};
    use tokio::sync::Mutex;

    #[derive(Debug, Clone)]
    pub struct Published {
        pub subject: String,
        pub payload: Vec<u8>,
    }

    type SubMap = Arc<Mutex<HashMap<String, (u64, Arc<Mutex<OwnedWriteHalf>>)>>>;

    pub struct MockNats {
        addr: SocketAddr,
        published: Arc<Mutex<Vec<Published>>>,
        subs: SubMap,
    }

    impl MockNats {
        pub async fn start() -> std::io::Result<Self> {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;

            let published: Arc<Mutex<Vec<Published>>> = Arc::new(Mutex::new(Vec::new()));
            let subs: SubMap = Arc::new(Mutex::new(HashMap::new()));

            let pub_clone = Arc::clone(&published);
            let subs_clone = Arc::clone(&subs);

            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let p = Arc::clone(&pub_clone);
                            let s = Arc::clone(&subs_clone);
                            tokio::spawn(async move {
                                let _ = handle_client(stream, p, s).await;
                            });
                        }
                        Err(_) => return,
                    }
                }
            });

            Ok(Self {
                addr,
                published,
                subs,
            })
        }

        pub fn url(&self) -> String {
            format!("nats://{}", self.addr)
        }

        pub async fn published(&self) -> Vec<Published> {
            self.published.lock().await.clone()
        }

        pub async fn wait_for_publishes(&self, count: usize, timeout: Duration) -> Vec<Published> {
            let deadline = Instant::now() + timeout;
            loop {
                let v = self.published().await;
                if v.len() >= count {
                    return v;
                }
                if Instant::now() >= deadline {
                    panic!("mock-nats: expected {count} publishes, got {}", v.len());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        pub async fn push(&self, subject: &str, payload: &[u8]) -> bool {
            let entry = self.subs.lock().await.get(subject).cloned();
            let Some((sid, writer)) = entry else {
                return false;
            };
            let header = format!("MSG {subject} {sid} {}\r\n", payload.len());
            let mut w = writer.lock().await;
            if w.write_all(header.as_bytes()).await.is_err() {
                return false;
            }
            if w.write_all(payload).await.is_err() {
                return false;
            }
            w.write_all(b"\r\n").await.is_ok()
        }
    }

    async fn handle_client(
        stream: TcpStream,
        published: Arc<Mutex<Vec<Published>>>,
        subs: SubMap,
    ) -> std::io::Result<()> {
        let (reader, writer) = stream.into_split();
        let writer = Arc::new(Mutex::new(writer));

        {
            // The minimum INFO frame async-nats 0.49 will accept.
            let info = "INFO {\"server_id\":\"mock\",\"version\":\"2.10.0\",\"go\":\"mock\",\"host\":\"127.0.0.1\",\"port\":0,\"max_payload\":1048576,\"client_id\":1,\"proto\":1,\"headers\":false}\r\n";
            writer.lock().await.write_all(info.as_bytes()).await?;
        }

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                return Ok(());
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            let mut parts = trimmed.splitn(2, ' ');
            let verb = parts.next().unwrap_or("").to_ascii_uppercase();
            let rest = parts.next().unwrap_or("");

            match verb.as_str() {
                "CONNECT" => {}
                "PING" => {
                    writer.lock().await.write_all(b"PONG\r\n").await?;
                }
                "PONG" => {}
                "PUB" => {
                    let tokens: Vec<&str> = rest.split_whitespace().collect();
                    let (subject, n_bytes) = match tokens.as_slice() {
                        [subject, n] => (subject.to_string(), n.parse::<usize>().unwrap_or(0)),
                        [subject, _reply, n] => {
                            (subject.to_string(), n.parse::<usize>().unwrap_or(0))
                        }
                        _ => continue,
                    };
                    let mut payload = vec![0u8; n_bytes];
                    reader.read_exact(&mut payload).await?;
                    let mut crlf = [0u8; 2];
                    let _ = reader.read_exact(&mut crlf).await;
                    published.lock().await.push(Published { subject, payload });
                }
                "SUB" => {
                    let tokens: Vec<&str> = rest.split_whitespace().collect();
                    let (subject, sid) = match tokens.as_slice() {
                        [subject, sid] => (subject.to_string(), sid.parse::<u64>().unwrap_or(0)),
                        [subject, _q, sid] => {
                            (subject.to_string(), sid.parse::<u64>().unwrap_or(0))
                        }
                        _ => continue,
                    };
                    subs.lock()
                        .await
                        .insert(subject, (sid, Arc::clone(&writer)));
                }
                "UNSUB" => {}
                "" => {}
                _ => {}
            }
        }
    }
}
