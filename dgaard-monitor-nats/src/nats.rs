//! Optional NATS publisher + subscriber for federating monitors.
//!
//! When `[nats] enabled = true`, the monitor:
//!   1. **Publishes** every enriched event produced by the local dgaard
//!      daemon on `publish_subject` (empty string disables this leg).
//!   2. **Subscribes** to `subscribe_subject` and feeds every incoming
//!      event into the local stats and broadcast, tagged as remote (empty
//!      string disables this leg).
//!
//! Wire format (UTF-8 JSON, one event per message):
//! ```json
//! {
//!   "v": 1,                    // format version; absent means 1
//!   "ts": 1731000000,          // Unix seconds
//!   "domain_hash": 12345,      // hash in the publishing daemon's space
//!   "domain": "example.com",   // optional — when the publisher knows it
//!   "client_ip": "192.168.1.1",
//!   "action": "Blocked",
//!   "reasons": 1               // optional bitmask of StatBlockReason
//! }
//! ```
//! `action` is one of `Allowed`, `Proxied`, `Blocked`, `Suspicious`,
//! `HighlySuspicious`, `Override`, `Cached`, `UpstreamError`, `DnssecBogus`,
//! the names used by every other output.
//!
//! Compatibility: adding optional fields or actions does not change `v`.
//! Receivers ignore unknown fields and skip (and count) events with an
//! unknown action or an unknown version, like the socket protocol skips
//! messages it does not understand. Only an incompatible change bumps `v`.
//!
//! Cycles are prevented by provenance: inbound events go through
//! `AppState::record_remote_event` and the publisher reads
//! `AppState::subscribe_local`, so an event received on NATS is never
//! re-published. The connection also sets `no_echo` so that, when both
//! subjects are equal (shared bus), the server does not hand a monitor
//! back its own events, which would otherwise be counted twice.
//!
//! Inbound events are untrusted. Each one is fully validated (syntax of the
//! domain, client address, timestamp within `MAX_CLOCK_SKEW_SECS` of the
//! local clock) before it touches the state; a peer's domain only fills a
//! hash this monitor does not know yet, in a capped table; and rejections
//! are logged at most once per `REJECT_LOG_INTERVAL`.
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::config::{NatsConfig, validate_publish_subject, validate_subscribe_subject};
use dgaard_monitor_core::io::socket::Backoff;
use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatError, StatEvent};
use dgaard_monitor_core::state::{AppState, Sink};
use dgaard_monitor_core::util::{format_client_ip, parse_client_ip};

/// Longest domain name accepted from a peer (RFC 1035, presentation form).
const MAX_DOMAIN_LEN: usize = 253;
/// Longest DNS label.
const MAX_LABEL_LEN: usize = 63;
/// Inbound events further than this from the local clock are dropped, so a
/// peer cannot make the persistence writer flush on every event.
const MAX_CLOCK_SKEW_SECS: u64 = 3600;
/// Minimum interval between two log lines about dropped inbound events.
const REJECT_LOG_INTERVAL: Duration = Duration::from_secs(10);
/// How much of an invalid `client_ip` is echoed back in logs.
const MAX_ECHOED_LEN: usize = 64;
/// Bound on the final flush of queued publications at shutdown.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Version of the wire format this monitor writes and understands.
pub const WIRE_VERSION: u32 = 1;

fn wire_version_absent() -> u32 {
    // Messages from monitors predating the field are version 1.
    1
}

/// On-wire representation of a monitor event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireEvent {
    #[serde(default = "wire_version_absent")]
    pub v: u32,
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
    /// Answered from dgaard's response cache.
    Cached,
    /// SERVFAIL: the upstream resolution failed.
    UpstreamError,
    /// SERVFAIL: DNSSEC validation failed.
    DnssecBogus,
    /// Allowed by an explicit override (`StatAction::AllowedWithOverride`).
    Override,
    /// An action this monitor does not know, from a newer peer. The event is
    /// skipped instead of failing to parse.
    #[serde(other)]
    Unknown,
}

impl WireEvent {
    pub fn from_event(event: &StatEvent, domain: Option<String>) -> Self {
        let (action, reasons) = match &event.action {
            StatAction::Allowed => (WireAction::Allowed, 0),
            StatAction::AllowedWithOverride => (WireAction::Override, 0),
            StatAction::Proxied => (WireAction::Proxied, 0),
            StatAction::Blocked(r) => (WireAction::Blocked, r.bits()),
            StatAction::Suspicious(r) => (WireAction::Suspicious, r.bits()),
            StatAction::HighlySuspicious(r) => (WireAction::HighlySuspicious, r.bits()),
            StatAction::Cached => (WireAction::Cached, 0),
            StatAction::Error(StatError::Upstream) => (WireAction::UpstreamError, 0),
            StatAction::Error(StatError::DnssecBogus) => (WireAction::DnssecBogus, 0),
        };
        Self {
            v: WIRE_VERSION,
            ts: event.timestamp,
            domain_hash: event.domain_hash,
            domain,
            client_ip: format_client_ip(&event.client_ip),
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
            WireAction::Cached => StatAction::Cached,
            WireAction::UpstreamError => StatAction::Error(StatError::Upstream),
            WireAction::DnssecBogus => StatAction::Error(StatError::DnssecBogus),
            WireAction::Override => StatAction::AllowedWithOverride,
            WireAction::Unknown => return Err(ParseError::UnknownAction),
        };
        Ok(StatEvent {
            timestamp: self.ts,
            domain_hash: self.domain_hash,
            client_ip: parse_client_ip(&self.client_ip).ok_or_else(|| {
                ParseError::InvalidClientIp(self.client_ip.chars().take(MAX_ECHOED_LEN).collect())
            })?,
            action,
        })
    }
}

#[derive(Debug)]
pub enum ParseError {
    Malformed(serde_json::Error),
    InvalidClientIp(String),
    /// Not echoed: the content is untrusted and may hold escape sequences.
    InvalidDomain,
    TimestampOutOfRange(u64),
    /// Sent by a newer peer: skipped, not an error in the event itself.
    UnknownAction,
    UnsupportedVersion(u32),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Malformed(e) => write!(f, "malformed event: {e}"),
            // Debug formatting escapes control characters.
            ParseError::InvalidClientIp(s) => write!(f, "invalid client_ip {s:?}"),
            ParseError::InvalidDomain => write!(f, "invalid domain"),
            ParseError::UnknownAction => write!(f, "unknown action (newer peer?)"),
            ParseError::UnsupportedVersion(v) => {
                write!(
                    f,
                    "unsupported format version {v} (this monitor reads {WIRE_VERSION})"
                )
            }
            ParseError::TimestampOutOfRange(ts) => {
                write!(
                    f,
                    "timestamp {ts} more than {MAX_CLOCK_SKEW_SECS}s from local clock"
                )
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Normalize a peer-supplied domain: LDH labels (underscore allowed, for
/// names like `_dmarc`), 1–63 bytes each, 253 bytes overall, lowercased.
/// Anything else — control characters, spaces, escape sequences — is refused.
fn normalize_domain(domain: &str) -> Option<String> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
        return None;
    }
    let valid = domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    });
    valid.then(|| domain.to_ascii_lowercase())
}

/// Check every field of an inbound event before anything touches the state.
/// Returns the event and its normalized domain, if one was sent.
fn validate_inbound(
    mut wire: WireEvent,
    now: u64,
) -> Result<(StatEvent, Option<String>), ParseError> {
    if wire.v != WIRE_VERSION {
        return Err(ParseError::UnsupportedVersion(wire.v));
    }
    if wire.ts.abs_diff(now) > MAX_CLOCK_SKEW_SECS {
        return Err(ParseError::TimestampOutOfRange(wire.ts));
    }
    let domain = match wire.domain.take() {
        Some(domain) => Some(normalize_domain(&domain).ok_or(ParseError::InvalidDomain)?),
        None => None,
    };
    Ok((wire.into_event()?, domain))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Rate-limited reporting of dropped inbound events: the first one is logged
/// at once, later ones are counted and summarized at most once per
/// `REJECT_LOG_INTERVAL`, so a hostile publisher cannot flood stderr.
#[derive(Debug, Default)]
struct RejectLog {
    total: u64,
    pending: u64,
    last_report: Option<Instant>,
}

impl RejectLog {
    /// Count one rejection; returns the line to log, if one is due.
    fn record(&mut self, reason: &ParseError, now: Instant) -> Option<String> {
        self.total += 1;
        self.pending += 1;
        if self
            .last_report
            .is_some_and(|at| now.duration_since(at) < REJECT_LOG_INTERVAL)
        {
            return None;
        }
        let line = format!(
            "nats: dropped {} inbound event(s) ({} total), latest: {reason}",
            self.pending, self.total
        );
        self.pending = 0;
        self.last_report = Some(now);
        Some(line)
    }
}

/// Spawn the NATS publisher + subscriber tasks. Returns immediately if
/// `enabled` is false, both subjects are blank, or a subject is invalid.
///
/// The broker does not need to be up: the client connects in the background
/// and keeps reconnecting, so a broker started after the monitor (systemd,
/// docker compose) is picked up. Meanwhile subscriptions and publications
/// wait in the client's queue. The rest of the monitor never waits for NATS.
pub async fn run(cfg: NatsConfig, state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    if !cfg.enabled {
        return;
    }
    if cfg.publish_subject.is_empty() && cfg.subscribe_subject.is_empty() {
        eprintln!("nats: both publish_subject and subscribe_subject are empty, disabling");
        return;
    }
    // The config parser checks these too; this guards other callers, since an
    // invalid publish subject would fail every single publication.
    let subject_checks = [
        (
            "publish_subject",
            &cfg.publish_subject,
            validate_publish_subject(&cfg.publish_subject),
        ),
        (
            "subscribe_subject",
            &cfg.subscribe_subject,
            validate_subscribe_subject(&cfg.subscribe_subject),
        ),
    ];
    for (key, subject, check) in subject_checks {
        if let Err(e) = check {
            eprintln!("nats: invalid {key} {subject:?}: {e}, disabling");
            return;
        }
    }

    let connect = async_nats::ConnectOptions::new()
        .no_echo()
        .retry_on_initial_connect()
        .connect(&cfg.url);
    let client = tokio::select! {
        result = connect => match result {
            Ok(c) => c,
            Err(e) => {
                eprintln!("nats: cannot use {}: {e}, disabling", cfg.url);
                return;
            }
        },
        _ = shutdown.changed() => return,
    };
    eprintln!("nats: connecting to {} in the background", cfg.url);

    // ── Subscriber leg ──────────────────────────────────────────────────────
    let subscriber_task = (!cfg.subscribe_subject.is_empty()).then(|| {
        tokio::spawn(run_subscription(
            client.clone(),
            cfg.subscribe_subject.clone(),
            Arc::clone(&state),
            shutdown.clone(),
        ))
    });

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

/// Subscribe to `subject`, and subscribe again with backoff whenever that
/// fails or the subscription ends, until shutdown. A failed subscription used
/// to leave the monitor running with the publisher only.
async fn run_subscription(
    client: async_nats::Client,
    subject: String,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = Backoff::new();
    loop {
        match client.subscribe(subject.clone()).await {
            Ok(sub) => {
                backoff.reset();
                eprintln!("nats: subscribed to {subject}");
                run_subscriber(sub, Arc::clone(&state), &mut shutdown).await;
                if *shutdown.borrow() {
                    return;
                }
                eprintln!("nats: subscription to {subject} ended");
            }
            Err(e) => eprintln!("nats: subscribe to {subject} failed: {e}"),
        }
        let delay = backoff.next_delay();
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

/// `publish` only queues: flush what is pending so the last events are not
/// lost at shutdown, within `FLUSH_TIMEOUT`. Skipped when disconnected, as
/// nothing could be sent anyway.
async fn flush_before_exit(client: &async_nats::Client) {
    if client.connection_state() != async_nats::connection::State::Connected {
        return;
    }
    match tokio::time::timeout(FLUSH_TIMEOUT, client.flush()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("nats: final flush failed: {e}"),
        Err(_) => eprintln!("nats: final flush timed out after {FLUSH_TIMEOUT:?}"),
    }
}

async fn run_subscriber(
    mut sub: async_nats::Subscriber,
    state: Arc<AppState>,
    shutdown: &mut watch::Receiver<bool>,
) {
    let mut rejects = RejectLog::default();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            msg = sub.next() => {
                match msg {
                    Some(msg) => {
                        if let Err(e) = handle_inbound(&msg.payload, &state, unix_now()).await
                            && let Some(line) = rejects.record(&e, Instant::now())
                        {
                            eprintln!("{line}");
                        }
                    }
                    None => return, // subscription closed
                }
            }
        }
    }
}

/// Validate one inbound payload, then record it. Nothing reaches the state
/// unless the whole event is valid. Peers are untrusted: their mapping only
/// fills a hash this monitor does not know yet (see `insert_remote_domain`).
async fn handle_inbound(payload: &[u8], state: &AppState, now: u64) -> Result<(), ParseError> {
    let wire: WireEvent = serde_json::from_slice(payload).map_err(ParseError::Malformed)?;
    let (event, domain) = validate_inbound(wire, now)?;
    if let Some(domain) = domain {
        state.insert_remote_domain(event.domain_hash, domain).await;
    }
    state.record_remote_event(event).await;
    Ok(())
}

async fn run_publisher(
    client: async_nats::Client,
    subject: String,
    state: Arc<AppState>,
    shutdown: &mut watch::Receiver<bool>,
) {
    // Local events only: re-publishing what came in over NATS would loop.
    let mut rx = state.subscribe_local();
    let subject = async_nats::Subject::from(subject);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                flush_before_exit(&client).await;
                return;
            }
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
                        state.record_drop(Sink::NatsPublisher, n);
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
            v: WIRE_VERSION,
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

    const NOW: u64 = 1_700_000_000;

    fn make_state() -> Arc<AppState> {
        Arc::new(AppState::new(Duration::from_secs(3600)))
    }

    fn inbound(domain: Option<&str>, client_ip: &str, ts: u64) -> Vec<u8> {
        serde_json::to_vec(&WireEvent {
            v: WIRE_VERSION,
            ts,
            domain_hash: 0x42,
            domain: domain.map(str::to_string),
            client_ip: client_ip.to_string(),
            action: WireAction::Blocked,
            reasons: StatBlockReason::ABP_RULE.bits(),
        })
        .unwrap()
    }

    // --- Wire format compatibility ---

    /// Regression: `AllowedWithOverride` went out as `Allowed`, while every
    /// other output reports it as `Override`.
    #[test]
    fn override_round_trips_losslessly() {
        let original = StatEvent {
            timestamp: 1,
            domain_hash: 1,
            client_ip: ipv4_bytes(10, 0, 0, 1),
            action: StatAction::AllowedWithOverride,
        };
        let json = serde_json::to_string(&WireEvent::from_event(&original, None)).unwrap();
        assert!(json.contains(r#""action":"Override""#), "{json}");
        let decoded = serde_json::from_str::<WireEvent>(&json)
            .unwrap()
            .into_event()
            .unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn published_events_carry_the_format_version() {
        let wire = WireEvent::from_event(
            &StatEvent {
                timestamp: 1,
                domain_hash: 1,
                client_ip: ipv4_bytes(10, 0, 0, 1),
                action: StatAction::Allowed,
            },
            None,
        );
        let json = serde_json::to_string(&wire).unwrap();
        assert!(json.starts_with(r#"{"v":1,"#), "{json}");
    }

    fn raw_inbound(fields: &str) -> Vec<u8> {
        format!(r#"{{"ts":{NOW},"domain_hash":66,"client_ip":"10.0.0.1",{fields}}}"#).into_bytes()
    }

    /// Regression: an action from a newer monitor failed JSON parsing, so the
    /// event was treated as malformed. It is now recognised and skipped.
    #[tokio::test]
    async fn unknown_action_is_skipped_not_malformed() {
        let state = make_state();
        let payload = raw_inbound(r#""action":"FutureAction""#);
        let wire: WireEvent = serde_json::from_slice(&payload).unwrap();
        assert_eq!(wire.action, WireAction::Unknown);

        let err = handle_inbound(&payload, &state, NOW).await.unwrap_err();
        assert!(matches!(err, ParseError::UnknownAction), "{err}");
        assert_eq!(state.stats.read().await.total, 0);
    }

    /// Monitors predating the `v` field are still understood.
    #[tokio::test]
    async fn missing_version_means_version_one() {
        let state = make_state();
        let payload = raw_inbound(r#""action":"Allowed""#);
        handle_inbound(&payload, &state, NOW).await.unwrap();
        assert_eq!(state.stats.read().await.total, 1);
    }

    #[tokio::test]
    async fn unknown_version_is_skipped() {
        let state = make_state();
        for version in ["0", "2"] {
            let payload = raw_inbound(&format!(r#""v":{version},"action":"Allowed""#));
            let err = handle_inbound(&payload, &state, NOW).await.unwrap_err();
            assert!(matches!(err, ParseError::UnsupportedVersion(_)), "{err}");
        }
        assert_eq!(state.stats.read().await.total, 0);
    }

    /// Additive changes (new optional fields) must not break older readers.
    #[tokio::test]
    async fn unknown_fields_are_ignored() {
        let state = make_state();
        let payload =
            raw_inbound(r#""v":1,"action":"Blocked","reasons":1,"origin":"peer-7","hops":0"#);
        handle_inbound(&payload, &state, NOW).await.unwrap();
        assert_eq!(state.stats.read().await.blocked, 1);
    }

    #[tokio::test]
    async fn handle_inbound_records_event_and_domain() {
        let state = make_state();
        let payload = inbound(Some("Mapped.Test"), "10.0.0.1", NOW);
        handle_inbound(&payload, &state, NOW).await.unwrap();

        assert_eq!(
            state.domain_map.read().await.get(&0x42).map(String::as_str),
            Some("mapped.test")
        );
        let stats = state.stats.read().await;
        assert_eq!(stats.total, 1);
        assert_eq!(stats.blocked, 1);
    }

    #[tokio::test]
    async fn handle_inbound_drops_garbage() {
        let state = make_state();
        let err = handle_inbound(b"not json", &state, NOW).await.unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
        assert_eq!(state.stats.read().await.total, 0);
    }

    /// Regression: the mapping used to be stored before the event was
    /// validated, so a rejected event could still rename a hash.
    #[tokio::test]
    async fn rejected_event_leaves_domain_map_untouched() {
        let state = make_state();
        let payload = inbound(Some("google.com"), "not-an-ip", NOW);
        let err = handle_inbound(&payload, &state, NOW).await.unwrap_err();
        assert!(matches!(err, ParseError::InvalidClientIp(_)));
        assert!(state.domain_map.read().await.is_empty());
        assert_eq!(state.stats.read().await.total, 0);
    }

    #[tokio::test]
    async fn peer_cannot_rename_a_known_hash() {
        let state = make_state();
        state.insert_domain(0x42, "evil.test".to_string()).await;
        let payload = inbound(Some("google.com"), "10.0.0.1", NOW);
        handle_inbound(&payload, &state, NOW).await.unwrap();

        assert_eq!(
            state.domain_map.read().await.get(&0x42).map(String::as_str),
            Some("evil.test")
        );
        // The event itself is still counted.
        assert_eq!(state.stats.read().await.total, 1);
    }

    #[tokio::test]
    async fn control_characters_in_domain_are_rejected() {
        let state = make_state();
        for domain in ["evil.test\nFAKE LOG LINE", "\u{1b}[31mred.test", "a b.test"] {
            let payload = inbound(Some(domain), "10.0.0.1", NOW);
            let err = handle_inbound(&payload, &state, NOW).await.unwrap_err();
            assert!(matches!(err, ParseError::InvalidDomain), "{domain:?}");
        }
        assert!(state.domain_map.read().await.is_empty());
        assert_eq!(state.stats.read().await.total, 0);
    }

    #[tokio::test]
    async fn timestamps_far_from_local_clock_are_rejected() {
        let state = make_state();
        for ts in [
            0,
            NOW - MAX_CLOCK_SKEW_SECS - 1,
            NOW + MAX_CLOCK_SKEW_SECS + 1,
        ] {
            let payload = inbound(None, "10.0.0.1", ts);
            let err = handle_inbound(&payload, &state, NOW).await.unwrap_err();
            assert!(matches!(err, ParseError::TimestampOutOfRange(_)), "{ts}");
        }
        for ts in [NOW - MAX_CLOCK_SKEW_SECS, NOW + MAX_CLOCK_SKEW_SECS] {
            let payload = inbound(None, "10.0.0.1", ts);
            handle_inbound(&payload, &state, NOW).await.unwrap();
        }
        assert_eq!(state.stats.read().await.total, 2);
    }

    #[test]
    fn invalid_client_ip_is_truncated_in_errors() {
        let huge = "x".repeat(10_000);
        let wire: WireEvent = serde_json::from_slice(&inbound(None, &huge, NOW)).unwrap();
        match wire.into_event() {
            Err(ParseError::InvalidClientIp(echoed)) => assert_eq!(echoed.len(), MAX_ECHOED_LEN),
            other => panic!("expected InvalidClientIp, got {other:?}"),
        }
    }

    #[test]
    fn normalize_domain_accepts_dns_names() {
        assert_eq!(
            normalize_domain("Example.COM").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("example.com.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("_dmarc.xn--bcher-kva.example").as_deref(),
            Some("_dmarc.xn--bcher-kva.example")
        );
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(longest.len(), MAX_DOMAIN_LEN);
        assert!(normalize_domain(&longest).is_some());
    }

    #[test]
    fn normalize_domain_rejects_everything_else() {
        let too_long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        let long_label = format!("{}.test", "a".repeat(MAX_LABEL_LEN + 1));
        for domain in [
            "",
            ".",
            "a..b",
            ".lead.test",
            too_long.as_str(),
            long_label.as_str(),
            "evil.test\n",
            "\u{1b}[31m.test",
            "a b.test",
            "slash/.test",
            "\u{e9}t\u{e9}.test",
        ] {
            assert!(normalize_domain(domain).is_none(), "{domain:?}");
        }
    }

    #[test]
    fn reject_log_is_rate_limited() {
        let mut log = RejectLog::default();
        let start = Instant::now();
        let reason = ParseError::InvalidDomain;

        let first = log
            .record(&reason, start)
            .expect("first rejection is logged");
        assert!(
            first.contains("dropped 1 inbound event(s) (1 total)"),
            "{first}"
        );
        for offset in 1..100 {
            assert!(
                log.record(&reason, start + Duration::from_millis(offset))
                    .is_none()
            );
        }
        let summary = log
            .record(&reason, start + REJECT_LOG_INTERVAL)
            .expect("summary after the interval");
        assert!(
            summary.contains("dropped 100 inbound event(s) (101 total)"),
            "{summary}"
        );
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
    use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatEvent};
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
        let probe = format!(
            "{{\"ts\":{},\"domain_hash\":0,\"client_ip\":\"0.0.0.0\",\"action\":\"Allowed\",\"reasons\":0}}",
            unix_now()
        );
        let probe = probe.as_bytes();
        while !mock.push("dgaard.events", probe).await {
            assert!(
                std::time::Instant::now() < deadline,
                "subscriber never registered"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let wire = WireEvent {
            v: WIRE_VERSION,
            ts: unix_now(),
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

    /// Regression for the federation loop: with identical subjects, an event
    /// received on NATS must not be re-published, while local events still are.
    #[tokio::test]
    async fn inbound_event_is_not_republished() {
        let mock = MockNats::start().await.unwrap();
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let cfg = NatsConfig {
            enabled: true,
            url: mock.url(),
            publish_subject: "dgaard.events".to_string(),
            subscribe_subject: "dgaard.events".to_string(),
        };

        let s = Arc::clone(&state);
        let handle = tokio::spawn(async move {
            super::run(cfg, s, shutdown_rx).await;
        });

        let wire = WireEvent {
            v: WIRE_VERSION,
            ts: unix_now(),
            domain_hash: 7,
            domain: Some("remote.test".to_string()),
            client_ip: "10.0.0.9".to_string(),
            action: WireAction::Blocked,
            reasons: StatBlockReason::STATIC_BLACKLIST.bits(),
        };
        let payload = serde_json::to_vec(&wire).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !mock.push("dgaard.events", &payload).await {
            assert!(
                std::time::Instant::now() < deadline,
                "subscriber never registered"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while state.stats.read().await.total < 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "inbound event never reached AppState"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Give a (buggy) publisher time to echo the inbound event, then emit
        // a local one: only the local event may reach the broker.
        tokio::time::sleep(Duration::from_millis(150)).await;
        state.record_event(sample_event()).await;
        let pubs = mock.wait_for_publishes(1, Duration::from_secs(2)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let pubs_after = mock.published().await;

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        assert_eq!(pubs_after.len(), 1, "unexpected publishes: {pubs_after:?}");
        let published: WireEvent = serde_json::from_slice(&pubs[0].payload).unwrap();
        assert_eq!(published.domain_hash, 0xabc);
    }

    #[tokio::test]
    async fn connection_disables_server_echo() {
        let mock = MockNats::start().await.unwrap();
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let cfg = NatsConfig {
            enabled: true,
            url: mock.url(),
            publish_subject: "dgaard.events".to_string(),
            subscribe_subject: String::new(),
        };

        let handle = tokio::spawn(super::run(cfg, state, shutdown_rx));

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let connect = loop {
            if let Some(connect) = mock.connects().await.into_iter().next() {
                break connect;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "client never sent CONNECT"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        let options: serde_json::Value = serde_json::from_str(&connect).unwrap();
        assert_eq!(options["echo"], serde_json::Value::Bool(false));
    }

    /// Regression: if the broker was not up when the monitor started (systemd,
    /// docker compose), NATS was disabled for the whole run.
    #[tokio::test]
    async fn broker_started_after_the_monitor_is_picked_up() {
        // Reserve a port nothing listens on yet.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let cfg = NatsConfig {
            enabled: true,
            url: format!("nats://{addr}"),
            publish_subject: "dgaard.events".to_string(),
            subscribe_subject: "upstream.events".to_string(),
        };
        let handle = tokio::spawn(super::run(cfg, Arc::clone(&state), shutdown_rx));

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !handle.is_finished(),
            "NATS gave up while the broker was down"
        );
        let mock = MockNats::start_on(&addr.to_string()).await.unwrap();

        // Subscriber leg: the queued SUB reaches the broker once connected.
        let probe = format!(
            "{{\"ts\":{},\"domain_hash\":1,\"client_ip\":\"10.0.0.2\",\"action\":\"Allowed\"}}",
            unix_now()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !mock.push("upstream.events", probe.as_bytes()).await {
            assert!(std::time::Instant::now() < deadline, "never subscribed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while state.stats.read().await.total < 1 {
            assert!(std::time::Instant::now() < deadline, "inbound event lost");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Publisher leg.
        state.record_event(sample_event()).await;
        let pubs = mock.wait_for_publishes(1, Duration::from_secs(5)).await;
        assert_eq!(pubs[0].subject, "dgaard.events");

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;
    }

    /// Regression: `connect` could not be interrupted by shutdown.
    #[tokio::test]
    async fn shutdown_is_prompt_while_the_broker_is_unreachable() {
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let cfg = NatsConfig {
            enabled: true,
            url: "nats://127.0.0.1:1".to_string(),
            publish_subject: "dgaard.events".to_string(),
            subscribe_subject: "upstream.events".to_string(),
        };
        let handle = tokio::spawn(super::run(cfg, state, shutdown_rx));
        tokio::time::sleep(Duration::from_millis(200)).await;

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("run() must stop promptly without a broker")
            .unwrap();
    }

    #[tokio::test]
    async fn invalid_subject_disables_nats_without_dialling() {
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (_tx, rx) = watch::channel(false);
        let cfg = NatsConfig {
            enabled: true,
            url: "nats://127.0.0.1:1".to_string(),
            publish_subject: "dgaard.*".to_string(),
            subscribe_subject: String::new(),
        };
        tokio::time::timeout(Duration::from_secs(1), super::run(cfg, state, rx))
            .await
            .expect("invalid subject must disable NATS at once");
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
        connects: Arc<Mutex<Vec<String>>>,
    }

    impl MockNats {
        pub async fn start() -> std::io::Result<Self> {
            Self::start_on("127.0.0.1:0").await
        }

        /// Start on a given address, e.g. to come up after a client tried it.
        pub async fn start_on(addr: &str) -> std::io::Result<Self> {
            let listener = TcpListener::bind(addr).await?;
            let addr = listener.local_addr()?;

            let published: Arc<Mutex<Vec<Published>>> = Arc::new(Mutex::new(Vec::new()));
            let subs: SubMap = Arc::new(Mutex::new(HashMap::new()));
            let connects: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

            let pub_clone = Arc::clone(&published);
            let subs_clone = Arc::clone(&subs);
            let connects_clone = Arc::clone(&connects);

            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let p = Arc::clone(&pub_clone);
                            let s = Arc::clone(&subs_clone);
                            let c = Arc::clone(&connects_clone);
                            tokio::spawn(async move {
                                let _ = handle_client(stream, p, s, c).await;
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
                connects,
            })
        }

        pub fn url(&self) -> String {
            format!("nats://{}", self.addr)
        }

        pub async fn published(&self) -> Vec<Published> {
            self.published.lock().await.clone()
        }

        /// JSON option blocks of every CONNECT frame received so far.
        pub async fn connects(&self) -> Vec<String> {
            self.connects.lock().await.clone()
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
        connects: Arc<Mutex<Vec<String>>>,
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
                "CONNECT" => connects.lock().await.push(rest.to_string()),
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
