//! Verify that TLS + DoH plumbing produces the expected settings on the wire.

use std::sync::Arc;

use digaard::transport::{
    DohMethod, DohSettings, ServerPicker, ServerStrategy, TlsSettings, TransportConfig,
};

fn cfg(server: &str) -> Arc<TransportConfig> {
    Arc::new(TransportConfig {
        server: server.to_string(),
        ..TransportConfig::default()
    })
}

#[test]
fn default_transport_config_has_sensible_defaults() {
    let c = TransportConfig::default();
    assert_eq!(c.port, 53);
    assert_eq!(c.timeout_ms, 5000);
    assert!(!c.tls.insecure);
    assert!(c.tls.servername.is_none());
    assert!(c.tls.extra_ca_pem.is_empty());
    assert_eq!(c.doh.method, DohMethod::Post);
    assert_eq!(c.doh.path, "/dns-query");
}

#[test]
fn custom_tls_and_doh_flow_into_config() {
    let c = TransportConfig {
        server: "dns.example".to_string(),
        port: 443,
        tls: TlsSettings {
            servername: Some("override.example".to_string()),
            insecure: true,
            extra_ca_pem: vec![b"-----BEGIN CERTIFICATE-----\n".to_vec()],
        },
        doh: DohSettings {
            method: DohMethod::Get,
            path: "/custom-path".to_string(),
        },
        ..TransportConfig::default()
    };
    assert_eq!(c.tls.servername.as_deref(), Some("override.example"));
    assert!(c.tls.insecure);
    assert_eq!(c.tls.extra_ca_pem.len(), 1);
    assert_eq!(c.doh.method, DohMethod::Get);
    assert_eq!(c.doh.path, "/custom-path");
}

#[test]
fn server_picker_first_ignores_other_servers() {
    let picker = ServerPicker::new(vec![cfg("a"), cfg("b"), cfg("c")], ServerStrategy::First);
    for _ in 0..10 {
        assert_eq!(picker.next().server, "a");
    }
}

#[test]
fn server_picker_round_robin_visits_each() {
    let picker = ServerPicker::new(
        vec![cfg("a"), cfg("b"), cfg("c")],
        ServerStrategy::RoundRobin,
    );
    let seen: Vec<String> = (0..6).map(|_| picker.next().server.clone()).collect();
    assert_eq!(seen, vec!["a", "b", "c", "a", "b", "c"]);
}

#[test]
fn server_picker_race_returns_all_configs() {
    let picker = ServerPicker::new(vec![cfg("a"), cfg("b")], ServerStrategy::Race);
    let names: Vec<&str> = picker.all().iter().map(|c| c.server.as_str()).collect();
    assert_eq!(names, vec!["a", "b"]);
    assert_eq!(picker.strategy(), ServerStrategy::Race);
}

#[test]
#[should_panic(expected = "at least one server")]
fn empty_server_list_is_a_hard_error() {
    let _ = ServerPicker::new(vec![], ServerStrategy::First);
}
