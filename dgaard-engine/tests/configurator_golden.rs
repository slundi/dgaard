//! The web configurator (`dgaard-web-configurator/`) emits `config.toml` from a
//! schema hand-transcribed from `src/config/parser.rs`. A transcription can be
//! wrong in ways no JavaScript test can catch — a key spelled differently, an
//! enum string the parser does not accept, a value shape TOML allows but the
//! parser rejects.
//!
//! These tests close that gap: they run the generator's checked-in output
//! through the real `Config::parse` and `Config::validate`. If the page starts
//! emitting something dgaard would refuse to start on, CI fails here.
//!
//! The golden files are regenerated with `just configurator-golden`; the
//! JavaScript side asserts they match what the emitter currently produces, so
//! the two halves cannot drift apart silently.

use dgaard_engine::Config;
use dgaard_engine::config::IdnMode;

/// Golden files live outside this crate, next to the page that generates them.
fn golden(name: &str) -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dgaard-web-configurator/tests/golden/"
    );
    let full = format!("{path}{name}");
    std::fs::read_to_string(&full)
        .unwrap_or_else(|err| panic!("cannot read {full}: {err} (run `just configurator-golden`)"))
}

fn parse_and_validate(name: &str) -> Config {
    let content = golden(name);
    let config =
        Config::parse(&content).unwrap_or_else(|err| panic!("{name} does not parse: {err}"));
    config
        .validate()
        .unwrap_or_else(|err| panic!("{name} parses but fails validation: {err}"));
    config
}

#[test]
fn annotated_default_config_parses_and_validates() {
    parse_and_validate("config.default.annotated.toml");
}

#[test]
fn annotated_default_config_round_trips_to_the_defaults() {
    // Everything the generator writes in this file is a default, so parsing it
    // must land exactly on `Config::default()`. This is the strongest possible
    // check that the schema's declared defaults match the Rust ones — a single
    // drifted default fails here.
    let parsed = parse_and_validate("config.default.annotated.toml");
    let expected = Config::default();

    assert_eq!(parsed.server, expected.server, "[server] defaults drifted");
    assert_eq!(
        parsed.security, expected.security,
        "[security] defaults drifted"
    );
    assert_eq!(
        parsed.forwarder, expected.forwarder,
        "[forwarder] defaults drifted"
    );
    assert_eq!(
        parsed.recursive, expected.recursive,
        "[recursive] defaults drifted"
    );
    assert_eq!(parsed.tld, expected.tld, "[tld] defaults drifted");
    assert_eq!(
        parsed.nxdomain_hunting, expected.nxdomain_hunting,
        "[nxdomain_hunting] defaults drifted"
    );
    assert_eq!(
        parsed.tunneling_detection, expected.tunneling_detection,
        "[tunneling_detection] defaults drifted"
    );
    assert_eq!(
        parsed.sources, expected.sources,
        "[sources] defaults drifted"
    );
    assert_eq!(parsed.abp, expected.abp, "[abp] defaults drifted");
    assert_eq!(parsed.cache, expected.cache, "[cache] defaults drifted");
    assert_eq!(
        parsed.prefetch, expected.prefetch,
        "[prefetch] defaults drifted"
    );
    assert!(
        parsed.overrides.is_empty(),
        "[[overrides]] should be empty by default"
    );
}

#[test]
fn annotated_populated_config_parses_and_validates() {
    parse_and_validate("config.populated.annotated.toml");
}

#[test]
fn minimal_populated_config_parses_and_validates() {
    parse_and_validate("config.populated.minimal.toml");
}

#[test]
fn both_output_modes_describe_the_same_configuration() {
    // Annotated writes every key, minimal writes only the overrides and lets
    // the parser fill in the rest. The two must land on the same `Config`.
    let annotated = parse_and_validate("config.populated.annotated.toml");
    let minimal = parse_and_validate("config.populated.minimal.toml");

    assert_eq!(annotated.server, minimal.server);
    assert_eq!(annotated.security, minimal.security);
    assert_eq!(annotated.forwarder, minimal.forwarder);
    assert_eq!(annotated.recursive, minimal.recursive);
    assert_eq!(annotated.tld, minimal.tld);
    assert_eq!(annotated.sources, minimal.sources);
    assert_eq!(annotated.overrides, minimal.overrides);
}

#[test]
fn the_populated_golden_exercises_the_awkward_shapes() {
    // A golden that only covered scalars would prove very little; assert the
    // fixture really carries the shapes most likely to be transcribed wrong.
    let config = parse_and_validate("config.populated.minimal.toml");

    assert_eq!(config.overrides.len(), 3, "overrides array-of-tables");
    assert!(
        config.overrides.iter().any(|entry| entry.to.is_ipv6()),
        "an IPv6 override address"
    );
    assert_eq!(
        config.security.custom_flags.len(),
        2,
        "custom_flags array-of-tables"
    );
    assert_eq!(config.security.custom_flags[0].bit, 16);
    assert_eq!(config.security.custom_flags[1].code, "HONEYPOT");

    assert_eq!(
        config.server.metrics_listen.as_deref(),
        Some("0.0.0.0:9153"),
        "a set Option<String>"
    );
    assert_eq!(
        config.security.low_ttl.min_ttl_floor_secs,
        Some(30),
        "a set Option<u32>"
    );
    assert_eq!(
        config.recursive.root_hints_path.as_deref(),
        Some("/etc/dgaard/root.hints"),
        "a set Option<String> in [recursive]"
    );

    assert_eq!(
        config.security.qtype_warden.blocked_types,
        vec![10, 13, 252, 255],
        "an int array"
    );
    assert!(
        (config.security.intelligence.entropy_threshold - 4.2).abs() < f32::EPSILON,
        "a float value"
    );
    assert_eq!(config.server.pipeline.len(), 5, "a shortened pipeline");
}

#[test]
fn the_populated_golden_covers_the_idn_cross_field_rule() {
    // `security.idn.mode != Off` is only valid when both coarse gates are off.
    // The generator must be able to emit that combination without tripping
    // `Config::validate` — this is the rule most likely to be got wrong.
    let config = parse_and_validate("config.populated.minimal.toml");

    assert!(!config.server.block_idn);
    assert!(!config.security.structure.force_lowercase_ascii);
    assert_ne!(config.security.idn.mode, IdnMode::Off);
}
