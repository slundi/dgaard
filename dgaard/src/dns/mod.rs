pub mod dnssec_chain;
pub mod packet;
pub mod recursive;
pub mod resolver;
pub(crate) mod upstream;

pub(crate) use dgaard_engine::model::InspectedAnswer;

use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::config::DnssecAction;
use crate::config::ResolutionMode;
use crate::config::ScoringConfig;
use crate::debug::debug_print;
use crate::dns::dnssec_chain::DnssecVerdict;
use crate::dns::packet::DnsPacket;
use crate::dns::resolver::UPSTREAM_RESOLVER;
use crate::dnssec::DnssecStatus;
use crate::model::{Action, StatAction, StatBlockReason, SuspicionScore};
use crate::resolve::{check_qclass, check_qtype, resolve_with_score, score_answer};
use crate::{CONFIG, STATS_COUNTERS, STATS_SENDER};

/// Resolve a clean query via the configured backend.
///
/// In Phase 1 the only backend is the legacy UDP forwarder, wrapped behind
/// [`crate::dns::resolver::UpstreamResolver`]. The fallback path keeps
/// existing tests that never call `install()` working: they exercise the
/// forwarder directly without setting up the global resolver.
async fn resolve_via_upstream(packet: &DnsPacket) -> std::io::Result<Vec<u8>> {
    match UPSTREAM_RESOLVER.get() {
        Some(resolver) => resolver.resolve(packet).await,
        None => {
            // The resolver is installed during runtime startup. If it has
            // not been installed (smoke tests, library re-use), fall back
            // to the direct call — preserves identical wire behaviour.
            let bytes = packet
                .message
                .to_vec()
                .map_err(|e| std::io::Error::other(format!("encode query: {e}")))?;
            crate::dns::upstream::forward_to_upstream(&bytes).await
        }
    }
}

/// Translate the recursive validator's verdict on an upstream answer
/// into the `DnssecStatus` the surrounding code already understands.
///
/// Returns `Ok` when the validator is not applicable (not recursive
/// mode, DNSSEC disabled, or the response bytes don't parse), so the
/// caller can always treat this as a refinement of the forwarder-mode
/// side-channel result rather than a replacement.
fn recursive_dnssec_status(
    mode: ResolutionMode,
    enabled: bool,
    response_bytes: &[u8],
    qname: &hickory_resolver::proto::rr::Name,
    qtype: hickory_resolver::proto::rr::RecordType,
) -> DnssecStatus {
    if !enabled || !matches!(mode, ResolutionMode::Recursive) {
        return DnssecStatus::Ok;
    }
    let Ok(msg) = hickory_resolver::proto::op::Message::from_vec(response_bytes) else {
        return DnssecStatus::Ok;
    };
    // Session 3: validate_message_for cross-checks NSEC/NSEC3 denials
    // on NXDOMAIN/NODATA responses, so a signed zone that fails to
    // prove its own negative answer now reports Bogus instead of the
    // session-1 fail-open Insecure.
    match crate::RECURSIVE_DNSSEC.validate_message_for(&msg, qname, qtype) {
        DnssecVerdict::Bogus => DnssecStatus::Bogus,
        // Insecure → Ok is fail-open: the canonical "absence of proof
        // is not proof of absence" stance for unsigned zones, and the
        // correct posture before the resolver has built a chain.
        DnssecVerdict::Secure | DnssecVerdict::Insecure => DnssecStatus::Ok,
    }
}

/// Map a suspicion score to a stat action using the configured thresholds.
///
/// Returns `(is_blocked, stat_action)`. When `is_blocked` is `true` the caller
/// should return an NXDOMAIN response; otherwise the upstream bytes are
/// forwarded as-is.
fn classify_score(
    score: &SuspicionScore,
    scoring: &ScoringConfig,
    pass_action: StatAction,
) -> (bool, StatAction) {
    let reason = || {
        score
            .primary_reason()
            .map(StatBlockReason::from)
            .unwrap_or(StatBlockReason::SUSPICIOUS)
    };
    if score.total >= scoring.blocking_threshold {
        (true, StatAction::Blocked(reason()))
    } else if score.total >= scoring.highly_suspicious_threshold {
        (false, StatAction::HighlySuspicious(reason()))
    } else if scoring.log_suspicious && score.total >= scoring.suspicious_threshold {
        (false, StatAction::Suspicious(reason()))
    } else {
        (false, pass_action)
    }
}

/// Handle an incoming DNS query by running it through the filter pipeline.
///
/// This function:
/// 1. Parses the DNS packet
/// 2. QType/QClass wardens (cheap static checks)
/// 3. Hot-cache lookup — serves instantly if cached, skipping steps 4–6
/// 4. Runs the domain through the resolve pipeline
/// 5. Either blocks the query (NXDOMAIN) or forwards to upstream
/// 6. Sends the response back to the client
/// 7. Emits stats events for telemetry
pub(crate) async fn handle_query(
    socket: Arc<UdpSocket>,
    packet: Vec<u8>,
    peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    // 1. Parse DNS packet
    let dns_packet = match DnsPacket::from_bytes(&packet) {
        Some(p) => p,
        None => {
            // Malformed packet - silently drop
            return Ok(());
        }
    };

    // Increment total query counter
    STATS_COUNTERS.increment_total();
    debug_print!(
        "Query: {} from {} (qtype={}, qclass={})",
        dns_packet.domain,
        peer,
        dns_packet.qtype,
        dns_packet.qclass
    );

    // 2a. QType Warden: block forbidden query types before domain resolution.
    //     This is the cheapest check — a u16 lookup — so it runs first.
    if let Some(reason) = check_qtype(dns_packet.qtype) {
        STATS_COUNTERS.increment_blocked();
        let stat_reason = StatBlockReason::from(&reason);
        debug_print!(
            "QType block: {} qtype={}: {:?}",
            dns_packet.domain,
            dns_packet.qtype,
            stat_reason
        );
        let response = DnsPacket::build_nxdomain_response(&dns_packet.message);
        socket.send_to(&response, peer).await?;
        if let Some(sender) = STATS_SENDER.get() {
            sender.send_event(&dns_packet.domain, peer, StatAction::Blocked(stat_reason));
        }
        return Ok(());
    }

    // 2b. QClass Warden: refuse CHAOS class (qclass=3) reconnaissance queries.
    //     Responds with REFUSED rather than NXDOMAIN — the request is rejected
    //     by policy, not because the domain is non-existent.
    if let Some(reason) = check_qclass(dns_packet.qclass) {
        STATS_COUNTERS.increment_blocked();
        let stat_reason = StatBlockReason::from(&reason);
        debug_print!(
            "QClass block: {} qclass={}: {:?}",
            dns_packet.domain,
            dns_packet.qclass,
            stat_reason
        );
        let response = DnsPacket::build_refused_response(&dns_packet.message);
        socket.send_to(&response, peer).await?;
        if let Some(sender) = STATS_SENDER.get() {
            sender.send_event(&dns_packet.domain, peer, StatAction::Blocked(stat_reason));
        }
        return Ok(());
    }

    // 2c. Hot cache: serve a cached response before touching the filter pipeline.
    //     A hit skips resolve_with_score, upstream forwarding, and DNSSEC entirely.
    if let Some(cache) = crate::RESPONSE_CACHE.get() {
        let txid = [packet[0], packet[1]];
        if let Some((cached, remaining_ttl)) =
            cache.get_with_remaining_ttl(&dns_packet.domain, dns_packet.qtype, txid)
        {
            STATS_COUNTERS.increment_cached();
            // Popularity is recorded only here — by the time a response
            // is in the cache, the full filter pipeline has already
            // judged the domain "allowed", so the tracker never sees
            // blocked names. Blocklist reloads (Phase 4) clear both
            // RESPONSE_CACHE and POPULARITY_TRACKER together to keep
            // this invariant valid across policy changes.
            crate::POPULARITY_TRACKER.record_hit(&dns_packet.domain);

            // Phase 5: enqueue a prefetch when the entry is about to
            // expire so the next client hit stays cached. Fire-and-
            // forget — a full queue or absent worker is a no-op.
            let trigger = CONFIG.load().prefetch.ttl_remaining_trigger_secs;
            if trigger > 0 && remaining_ttl < trigger {
                crate::prefetch::try_enqueue(&dns_packet.domain, dns_packet.qtype);
            }

            socket.send_to(&cached, peer).await?;
            return Ok(());
        }
    }

    // 2d. Run domain through the filter pipeline
    let resolve_result = resolve_with_score(&dns_packet.domain);
    let action = resolve_result.action;
    let mut score = resolve_result.score;
    debug_print!(
        "Resolve: {} -> {:?} (score={})",
        dns_packet.domain,
        action,
        score.total
    );

    // 3. Process the action and determine stat action
    let cfg_snap = CONFIG.load();
    let scoring = &cfg_snap.security.scoring;
    let dnssec_cfg = cfg_snap.security.dnssec.clone();
    let server_mode = cfg_snap.server.mode;
    let cache_ttl_override = cfg_snap.cache.ttl_override;
    let low_ttl_floor = cfg_snap.security.low_ttl.min_ttl_floor_secs;
    let (response, stat_action) = match &action {
        Action::Allow => {
            let (upstream_result, dnssec_status) = if dnssec_cfg.enabled {
                tokio::join!(
                    resolve_via_upstream(&dns_packet),
                    crate::dnssec::validate(&dns_packet.domain, dns_packet.qtype),
                )
            } else {
                (resolve_via_upstream(&dns_packet).await, DnssecStatus::Ok)
            };
            // Phase 6 (session 1): in recursive mode the side-channel
            // validator is skipped at startup, so `dnssec_status` is
            // always Ok above. The recursive chain validator inspects
            // the answer bytes once they arrive (see the
            // `Ok(upstream_bytes)` arm).
            if dnssec_status == DnssecStatus::Bogus {
                if dnssec_cfg.action == DnssecAction::Block {
                    STATS_COUNTERS.increment_blocked();
                    socket
                        .send_to(
                            &DnsPacket::build_servfail_response(&dns_packet.message),
                            peer,
                        )
                        .await?;
                    return Ok(());
                } else {
                    log::warn!("DNSSEC BOGUS (log-only): {}", dns_packet.domain);
                }
            }
            match upstream_result {
                Ok(upstream_bytes) => {
                    // Recursive-mode validation runs on the bytes we
                    // just received; the chain primitives short-circuit
                    // to Ok when no DNSKEY for the zone is cached yet
                    // (Insecure → fail-open).
                    let (q_name, q_type) = dns_packet
                        .message
                        .queries
                        .first()
                        .map(|q| (q.name().clone(), q.query_type()))
                        .unwrap_or((
                            hickory_resolver::proto::rr::Name::root(),
                            hickory_resolver::proto::rr::RecordType::A,
                        ));
                    if recursive_dnssec_status(
                        server_mode,
                        dnssec_cfg.enabled,
                        &upstream_bytes,
                        &q_name,
                        q_type,
                    ) == DnssecStatus::Bogus
                    {
                        if dnssec_cfg.action == DnssecAction::Block {
                            STATS_COUNTERS.increment_blocked();
                            socket
                                .send_to(
                                    &DnsPacket::build_servfail_response(&dns_packet.message),
                                    peer,
                                )
                                .await?;
                            return Ok(());
                        }
                        log::warn!("DNSSEC BOGUS (recursive, log-only): {}", dns_packet.domain);
                    }
                    // DPI: score the upstream answer; block if it crosses the configured threshold
                    let inspected = InspectedAnswer::from_response(&upstream_bytes);
                    if let Some(answer) = &inspected {
                        score_answer(&mut score, answer);
                    }
                    let (is_blocked, stat_action) =
                        classify_score(&score, scoring, StatAction::Allowed);
                    if is_blocked {
                        STATS_COUNTERS.increment_blocked();
                        (
                            DnsPacket::build_nxdomain_response(&dns_packet.message),
                            Some(stat_action),
                        )
                    } else {
                        if let (Some(cache), Some(ttl)) = (
                            crate::RESPONSE_CACHE.get(),
                            inspected.and_then(|a| a.min_ttl),
                        ) {
                            let floored = low_ttl_floor.map_or(ttl, |f| ttl.max(f));
                            cache.insert(
                                &dns_packet.domain,
                                dns_packet.qtype,
                                &upstream_bytes,
                                floored,
                                cache_ttl_override,
                            );
                        }
                        STATS_COUNTERS.increment_allowed();
                        (upstream_bytes, Some(stat_action))
                    }
                }
                Err(_) => {
                    // Upstream timed out / refused; we send SERVFAIL to the
                    // client. This is neither Allowed nor Proxied — record
                    // it as an error so dashboards reflect reality.
                    STATS_COUNTERS.increment_upstream_errors();
                    (
                        DnsPacket::build_servfail_response(&dns_packet.message),
                        None,
                    )
                }
            }
        }
        Action::ProxyToUpstream => {
            let (upstream_result, dnssec_status) = if dnssec_cfg.enabled {
                tokio::join!(
                    resolve_via_upstream(&dns_packet),
                    crate::dnssec::validate(&dns_packet.domain, dns_packet.qtype),
                )
            } else {
                (resolve_via_upstream(&dns_packet).await, DnssecStatus::Ok)
            };
            if dnssec_status == DnssecStatus::Bogus {
                if dnssec_cfg.action == DnssecAction::Block {
                    STATS_COUNTERS.increment_blocked();
                    socket
                        .send_to(
                            &DnsPacket::build_servfail_response(&dns_packet.message),
                            peer,
                        )
                        .await?;
                    return Ok(());
                } else {
                    log::warn!("DNSSEC BOGUS (log-only): {}", dns_packet.domain);
                }
            }
            match upstream_result {
                Ok(upstream_bytes) => {
                    // Recursive-mode chain validation, mirrored from
                    // the Allow branch — see notes there.
                    let (q_name, q_type) = dns_packet
                        .message
                        .queries
                        .first()
                        .map(|q| (q.name().clone(), q.query_type()))
                        .unwrap_or((
                            hickory_resolver::proto::rr::Name::root(),
                            hickory_resolver::proto::rr::RecordType::A,
                        ));
                    if recursive_dnssec_status(
                        server_mode,
                        dnssec_cfg.enabled,
                        &upstream_bytes,
                        &q_name,
                        q_type,
                    ) == DnssecStatus::Bogus
                    {
                        if dnssec_cfg.action == DnssecAction::Block {
                            STATS_COUNTERS.increment_blocked();
                            socket
                                .send_to(
                                    &DnsPacket::build_servfail_response(&dns_packet.message),
                                    peer,
                                )
                                .await?;
                            return Ok(());
                        }
                        log::warn!("DNSSEC BOGUS (recursive, log-only): {}", dns_packet.domain);
                    }
                    // DPI: score the upstream answer; block if it crosses the configured threshold
                    let inspected = InspectedAnswer::from_response(&upstream_bytes);
                    if let Some(answer) = &inspected {
                        score_answer(&mut score, answer);
                    }
                    let (is_blocked, stat_action) =
                        classify_score(&score, scoring, StatAction::Proxied);
                    if is_blocked {
                        STATS_COUNTERS.increment_blocked();
                        (
                            DnsPacket::build_nxdomain_response(&dns_packet.message),
                            Some(stat_action),
                        )
                    } else {
                        if let (Some(cache), Some(ttl)) = (
                            crate::RESPONSE_CACHE.get(),
                            inspected.and_then(|a| a.min_ttl),
                        ) {
                            let floored = low_ttl_floor.map_or(ttl, |f| ttl.max(f));
                            cache.insert(
                                &dns_packet.domain,
                                dns_packet.qtype,
                                &upstream_bytes,
                                floored,
                                cache_ttl_override,
                            );
                        }
                        STATS_COUNTERS.increment_proxied();
                        (upstream_bytes, Some(stat_action))
                    }
                }
                Err(_) => {
                    STATS_COUNTERS.increment_upstream_errors();
                    (
                        DnsPacket::build_servfail_response(&dns_packet.message),
                        None,
                    )
                }
            }
        }
        Action::Block(reason) => {
            STATS_COUNTERS.increment_blocked();
            let stat_reason = StatBlockReason::from(reason);
            (
                DnsPacket::build_nxdomain_response(&dns_packet.message),
                Some(StatAction::Blocked(stat_reason)),
            )
        }
        Action::Drop => {
            STATS_COUNTERS.increment_blocked();
            return Ok(());
        }
        Action::LocalResolve(ip) | Action::Respond(ip) => {
            STATS_COUNTERS.increment_allowed();
            (
                DnsPacket::build_ip_response(&dns_packet.message, *ip),
                Some(StatAction::Allowed),
            )
        }
        Action::Redirect(ip) | Action::InternalRedirect(ip) => {
            STATS_COUNTERS.increment_proxied();
            (
                DnsPacket::build_ip_response(&dns_packet.message, *ip),
                Some(StatAction::Proxied),
            )
        }
        Action::Override(ip) => {
            STATS_COUNTERS.increment_allowed();
            (
                DnsPacket::build_ip_response(&dns_packet.message, *ip),
                Some(StatAction::AllowedWithOverride),
            )
        }
    };

    // 4. Send response back to client
    socket.send_to(&response, peer).await?;

    // 5. Emit stat event (non-blocking)
    if let Some(stat_action) = stat_action
        && let Some(sender) = STATS_SENDER.get()
    {
        sender.send_event(&dns_packet.domain, peer, stat_action);
    }

    Ok(())
}
