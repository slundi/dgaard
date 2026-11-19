//! The monitor reads what dgaard writes: every event shape, with and without
//! the GeoIP country trailer, encoded by `dgaard-engine` and decoded by
//! `dgaard-monitor-core`.

use dgaard_engine::model::{
    StatAction as EngineAction, StatBlockReason as EngineReason, StatError as EngineError,
    StatEvent as EngineEvent, StatMessage as EngineMessage,
};
use dgaard_monitor_core::protocol::{
    StatAction, StatBlockReason, StatError, StatEvent, StatMessage,
};

/// The same action on both sides of the socket.
fn actions() -> Vec<(EngineAction, StatAction)> {
    let bits = (1 << 1) | (1 << 15) | (1 << 30);
    vec![
        (EngineAction::Allowed, StatAction::Allowed),
        (EngineAction::Proxied, StatAction::Proxied),
        (
            EngineAction::Blocked(EngineReason::from_bits_retain(bits)),
            StatAction::Blocked(StatBlockReason::from_bits_retain(bits)),
        ),
        (
            EngineAction::Suspicious(EngineReason::from_bits_retain(bits)),
            StatAction::Suspicious(StatBlockReason::from_bits_retain(bits)),
        ),
        (
            EngineAction::HighlySuspicious(EngineReason::from_bits_retain(bits)),
            StatAction::HighlySuspicious(StatBlockReason::from_bits_retain(bits)),
        ),
        (
            EngineAction::AllowedWithOverride,
            StatAction::AllowedWithOverride,
        ),
        (EngineAction::Cached, StatAction::Cached),
        (
            EngineAction::Error(EngineError::Upstream),
            StatAction::Error(StatError::Upstream),
        ),
        (
            EngineAction::Error(EngineError::DnssecBogus),
            StatAction::Error(StatError::DnssecBogus),
        ),
    ]
}

#[test]
fn monitor_decodes_every_event_dgaard_encodes() {
    let client_ip = std::net::Ipv4Addr::new(192, 168, 1, 7)
        .to_ipv6_mapped()
        .octets();
    for country in [None, Some(*b"FR")] {
        for (engine_action, expected_action) in actions() {
            let frame = EngineMessage::Event(EngineEvent {
                timestamp: 1_731_000_000,
                domain_hash: 0x0123_4567_89ab_cdef,
                client_ip,
                action: engine_action,
                country,
            })
            .serialize();
            let decoded = StatMessage::deserialize(&frame);
            assert_eq!(
                decoded,
                Some(StatMessage::Event(StatEvent {
                    timestamp: 1_731_000_000,
                    domain_hash: 0x0123_4567_89ab_cdef,
                    client_ip,
                    action: expected_action,
                    country,
                })),
                "{engine_action:?} with {country:?}"
            );
        }
    }
}

#[test]
fn dgaard_decodes_every_event_the_monitor_encodes() {
    // The monitor re-encodes events (tests, fake daemons): same bytes back.
    for (engine_action, monitor_action) in actions() {
        let frame = StatMessage::Event(StatEvent {
            timestamp: 7,
            domain_hash: 9,
            client_ip: [1; 16],
            action: monitor_action,
            country: Some(*b"JP"),
        })
        .serialize();
        let Some(EngineMessage::Event(event)) = EngineMessage::deserialize(&frame) else {
            panic!("dgaard should read {engine_action:?}");
        };
        assert_eq!(event.action, engine_action);
        assert_eq!(event.country, Some(*b"JP"));
    }
}
