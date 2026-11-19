//! Federation tests: the full NATS publisher and subscriber against an
//! in-process mock broker (`mock_nats`).

mod mock_nats;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatEvent};
use dgaard_monitor_core::state::AppState;
use dgaard_monitor_nats::config::NatsConfig;
use dgaard_monitor_nats::{WIRE_VERSION, WireAction, WireEvent, run};
use tokio::sync::watch;

use mock_nats::MockNats;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

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
        run(cfg, s, shutdown_rx).await;
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
        run(cfg, s, shutdown_rx).await;
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
        run(cfg, s, shutdown_rx).await;
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

    let handle = tokio::spawn(run(cfg, state, shutdown_rx));

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
    let handle = tokio::spawn(run(cfg, Arc::clone(&state), shutdown_rx));

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
    let handle = tokio::spawn(run(cfg, state, shutdown_rx));
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
    tokio::time::timeout(Duration::from_secs(1), run(cfg, state, rx))
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

    tokio::time::timeout(Duration::from_secs(1), run(cfg, state, rx))
        .await
        .expect("disabled run() must return promptly");
}
