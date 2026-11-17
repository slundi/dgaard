pub mod dnssec_chain;
pub mod packet;
pub mod recursive;
pub mod resolver;
pub(crate) mod tcp;
pub(crate) mod upstream;

pub(crate) use dgaard_engine::model::InspectedAnswer;

use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::config::Config;
use crate::config::DnssecAction;
use crate::config::ResolutionMode;
use crate::config::ScoringConfig;
use crate::debug::debug_print;
use crate::dns::dnssec_chain::DnssecVerdict;
use crate::dns::packet::{DnsPacket, Incoming, Transport};
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
            crate::dns::upstream::forward_to_upstream(&bytes, packet.transport == Transport::Tcp)
                .await
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
    // Fail-closed under signed zones: missing, forged or expired
    // signatures and unproven denials there are Bogus.
    match crate::RECURSIVE_DNSSEC.validate_message_for(&msg, qname, qtype) {
        DnssecVerdict::Bogus => DnssecStatus::Bogus,
        // Insecure: unsigned zone (insecure delegation proven by the
        // parent) or no chain applies — nothing to verify against.
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

/// Decide, before any upstream traffic, whether a query the pipeline would
/// forward must already be blocked by its score.
///
/// For a DNS tunnel the query itself is the exfiltration channel, and a DGA
/// resolution is the C2 rendezvous: blocking the *answer* is too late. The
/// score only grows once the answer is inspected, so a query at or above
/// the blocking threshold here would be blocked after forwarding anyway.
pub(crate) fn block_before_upstream(
    action: &Action,
    score: &SuspicionScore,
    scoring: &ScoringConfig,
) -> Option<StatAction> {
    if !matches!(action, Action::Allow | Action::ProxyToUpstream) {
        return None;
    }
    match classify_score(score, scoring, StatAction::Proxied) {
        (true, stat_action) => Some(stat_action),
        (false, _) => None,
    }
}

/// Outcome of [`forward_and_inspect`].
pub(crate) enum ForwardOutcome {
    /// The answer passed every check; it was cached when it carries a TTL.
    Serve {
        bytes: Vec<u8>,
        stat_action: StatAction,
    },
    /// Answer inspection pushed the score over the threshold: NXDOMAIN.
    Blocked(StatAction),
    /// DNSSEC validation failed with `action = "block"`: SERVFAIL.
    Bogus,
    /// The upstream resolution failed: SERVFAIL.
    UpstreamError,
}

/// Drop any cached answer for `packet`'s name and type.
pub(crate) fn evict_cached(domain: &str, qtype: u16) {
    if let Some(cache) = crate::RESPONSE_CACHE.get() {
        cache.remove(domain, qtype);
    }
}

/// Post-processing every forwarded answer gets, whoever triggered the
/// resolution (`handle_query` or the prefetch worker): DNSSEC (side channel
/// in forwarder mode, chain validation in recursive mode), answer inspection
/// (rebinding shield, CNAME cloaking, ASN, low TTL…) and the score
/// threshold.
///
/// `upstream` is the pending resolution, run alongside the DNSSEC side
/// channel. An accepted answer is cached; a rejected one evicts the cached
/// entry for the same name and type, so a previous answer stops being
/// served once its refresh is refused.
pub(crate) async fn forward_and_inspect(
    packet: &DnsPacket,
    upstream: impl std::future::Future<Output = std::io::Result<Vec<u8>>>,
    mut score: SuspicionScore,
    pass_action: StatAction,
    cfg: &Config,
) -> ForwardOutcome {
    let dnssec_cfg = &cfg.security.dnssec;
    let (upstream_result, dnssec_status) = if dnssec_cfg.enabled {
        tokio::join!(
            upstream,
            crate::dnssec::validate(&packet.domain, packet.qtype)
        )
    } else {
        (upstream.await, DnssecStatus::Ok)
    };
    // In recursive mode the side channel is not started, so this is Ok and
    // the chain validator below judges the answer bytes instead.
    if dnssec_status == DnssecStatus::Bogus {
        if dnssec_cfg.action == DnssecAction::Block {
            evict_cached(&packet.domain, packet.qtype);
            return ForwardOutcome::Bogus;
        }
        log::warn!("DNSSEC BOGUS (log-only): {}", packet.domain);
    }

    let Ok(upstream_bytes) = upstream_result else {
        return ForwardOutcome::UpstreamError;
    };

    let (q_name, q_type) = packet
        .message
        .queries
        .first()
        .map(|q| (q.name().clone(), q.query_type()))
        .unwrap_or((
            hickory_resolver::proto::rr::Name::root(),
            hickory_resolver::proto::rr::RecordType::A,
        ));
    if recursive_dnssec_status(
        cfg.server.mode,
        dnssec_cfg.enabled,
        &upstream_bytes,
        &q_name,
        q_type,
    ) == DnssecStatus::Bogus
    {
        if dnssec_cfg.action == DnssecAction::Block {
            evict_cached(&packet.domain, packet.qtype);
            return ForwardOutcome::Bogus;
        }
        log::warn!("DNSSEC BOGUS (recursive, log-only): {}", packet.domain);
    }

    // DPI: score the upstream answer; block if it crosses the threshold.
    let inspected = InspectedAnswer::from_response(&upstream_bytes);
    if let Some(answer) = &inspected {
        score_answer(&mut score, answer);
    }
    let (is_blocked, stat_action) = classify_score(&score, &cfg.security.scoring, pass_action);
    if is_blocked {
        evict_cached(&packet.domain, packet.qtype);
        return ForwardOutcome::Blocked(stat_action);
    }

    if let (Some(cache), Some(ttl)) = (
        crate::RESPONSE_CACHE.get(),
        inspected.and_then(|a| a.min_ttl),
    ) {
        let floored = cfg
            .security
            .low_ttl
            .min_ttl_floor_secs
            .map_or(ttl, |floor| ttl.max(floor));
        cache.insert(
            &packet.domain,
            packet.qtype,
            &upstream_bytes,
            floored,
            cfg.cache.ttl_override,
        );
    }
    ForwardOutcome::Serve {
        bytes: upstream_bytes,
        stat_action,
    }
}

/// Answer one DNS message received over `transport`, whatever the transport:
/// returns the response to send, or `None` when nothing must be sent.
///
/// This function:
/// 1. Parses the DNS packet; drops responses and malformed datagrams,
///    answers other opcodes with NOTIMP and question counts ≠ 1 with FORMERR
/// 2. QType/QClass wardens (cheap static checks)
/// 3. Hot-cache lookup — serves instantly if cached, skipping steps 4–6
/// 4. Runs the domain through the resolve pipeline, and blocks it before any
///    upstream traffic when its score already reaches the blocking threshold
/// 5. Either blocks the query (NXDOMAIN) or forwards to upstream, then
///    re-scores with what the answer reveals
/// 6. Emits stats events for telemetry
///
/// Size limits are the transport's business: see [`handle_query`] for UDP.
pub(crate) async fn answer_query(
    packet: &[u8],
    peer: std::net::SocketAddr,
    transport: Transport,
) -> Option<Vec<u8>> {
    // 1. Parse and screen: only standard queries reach the pipeline, and a
    //    response is never answered (no reflection loop).
    let mut dns_packet = match DnsPacket::screen(packet) {
        Incoming::Query(p) => p,
        Incoming::Drop => return None,
        Incoming::Reject(response) => return Some(response),
    };
    dns_packet.transport = transport;

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
        if let Some(sender) = STATS_SENDER.get() {
            sender.send_event(&dns_packet.domain, peer, StatAction::Blocked(stat_reason));
        }
        return Some(DnsPacket::build_nxdomain_response(&dns_packet.message));
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
        if let Some(sender) = STATS_SENDER.get() {
            sender.send_event(&dns_packet.domain, peer, StatAction::Blocked(stat_reason));
        }
        return Some(DnsPacket::build_refused_response(&dns_packet.message));
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

            return Some(cached);
        }
    }

    // 2d. Run domain through the filter pipeline
    let resolve_result = resolve_with_score(&dns_packet.domain);
    let action = resolve_result.action;
    let score = resolve_result.score;
    debug_print!(
        "Resolve: {} -> {:?} (score={})",
        dns_packet.domain,
        action,
        score.total
    );

    // 3. Process the action and determine stat action
    let cfg_snap = CONFIG.load();
    let scoring = &cfg_snap.security.scoring;

    // 3a. Score gate before any upstream traffic; the post-answer check
    //     below only sees what answer inspection adds.
    if let Some(stat_action) = block_before_upstream(&action, &score, scoring) {
        STATS_COUNTERS.increment_blocked();
        debug_print!(
            "Pre-upstream score block: {} (score={})",
            dns_packet.domain,
            score.total
        );
        if let Some(sender) = STATS_SENDER.get() {
            sender.send_event(&dns_packet.domain, peer, stat_action);
        }
        return Some(DnsPacket::build_nxdomain_response(&dns_packet.message));
    }

    let (response, stat_action) = match &action {
        Action::Allow | Action::ProxyToUpstream => {
            let allowed = matches!(action, Action::Allow);
            let pass_action = if allowed {
                StatAction::Allowed
            } else {
                StatAction::Proxied
            };
            let upstream = resolve_via_upstream(&dns_packet);
            match forward_and_inspect(&dns_packet, upstream, score, pass_action, &cfg_snap).await {
                ForwardOutcome::Serve { bytes, stat_action } => {
                    if allowed {
                        STATS_COUNTERS.increment_allowed();
                    } else {
                        STATS_COUNTERS.increment_proxied();
                    }
                    (bytes, Some(stat_action))
                }
                ForwardOutcome::Blocked(stat_action) => {
                    STATS_COUNTERS.increment_blocked();
                    (
                        DnsPacket::build_nxdomain_response(&dns_packet.message),
                        Some(stat_action),
                    )
                }
                ForwardOutcome::Bogus => {
                    STATS_COUNTERS.increment_blocked();
                    (
                        DnsPacket::build_servfail_response(&dns_packet.message),
                        None,
                    )
                }
                ForwardOutcome::UpstreamError => {
                    // Upstream timed out / refused: neither Allowed nor
                    // Proxied, recorded as an error so dashboards reflect it.
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
            return None;
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

    // 4. Emit stat event (non-blocking)
    if let Some(stat_action) = stat_action
        && let Some(sender) = STATS_SENDER.get()
    {
        sender.send_event(&dns_packet.domain, peer, stat_action);
    }

    Some(response)
}

/// Handle a query received over UDP: answer it, then fit the response in
/// the payload size the client advertised (RFC 6891 §6.2.5; 512 bytes
/// without EDNS) — a bigger answer becomes TC=1 so the client retries over
/// TCP. Applies to every answer, cache hits included: an entry cached for an
/// EDNS-4096 client may be served to a 512-byte one.
pub(crate) async fn handle_query(
    socket: Arc<UdpSocket>,
    packet: Vec<u8>,
    peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    if let Some(response) = answer_query(&packet, peer, Transport::Udp).await {
        socket
            .send_to(&packet::fit_udp_response(&packet, response), peer)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use dgaard_engine::model::BlockReason;
    use hickory_resolver::proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_resolver::proto::rr::rdata::A;
    use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};

    use super::*;
    use crate::config::Config;
    use crate::dns::resolver::UpstreamResolver;
    use crate::resolve::tests::{create_test_engine, run_with_globals};
    use crate::{CONFIG, CURRENT_ENGINE};

    fn scoring_with_threshold(blocking_threshold: u8) -> ScoringConfig {
        ScoringConfig {
            blocking_threshold,
            ..ScoringConfig::default()
        }
    }

    fn score_of(points: u8) -> SuspicionScore {
        let mut score = SuspicionScore::new();
        score.add(points, BlockReason::NrdList);
        score
    }

    #[test]
    fn block_before_upstream_stops_forwarded_actions_over_threshold() {
        let scoring = scoring_with_threshold(5);
        for action in [Action::ProxyToUpstream, Action::Allow] {
            let stat = block_before_upstream(&action, &score_of(5), &scoring);
            assert!(
                matches!(stat, Some(StatAction::Blocked(_))),
                "{action:?}: got {stat:?}"
            );
        }
    }

    #[test]
    fn block_before_upstream_lets_low_scores_through() {
        let scoring = scoring_with_threshold(5);
        assert!(block_before_upstream(&Action::ProxyToUpstream, &score_of(4), &scoring).is_none());
    }

    #[test]
    fn block_before_upstream_ignores_actions_that_never_forward() {
        // These never reach upstream: the gate has nothing to stop.
        let scoring = scoring_with_threshold(1);
        let ip = std::net::IpAddr::from([10, 0, 0, 1]);
        for action in [
            Action::Block(BlockReason::NrdList),
            Action::Drop,
            Action::Override(ip),
            Action::LocalResolve(ip),
        ] {
            assert!(block_before_upstream(&action, &score_of(10), &scoring).is_none());
        }
    }

    // ---- handle_query end to end with a counting upstream ----

    /// Upstream calls seen by [`CountingResolver`] in this process.
    static UPSTREAM_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// Upstream stand-in: counts calls and answers every A query.
    struct CountingResolver;

    #[async_trait]
    impl UpstreamResolver for CountingResolver {
        async fn resolve(&self, query: &DnsPacket) -> std::io::Result<Vec<u8>> {
            UPSTREAM_CALLS.fetch_add(1, Ordering::SeqCst);
            let mut response = query.message.clone();
            response.metadata.message_type = MessageType::Response;
            response.metadata.response_code = ResponseCode::NoError;
            if let Some(question) = query.message.queries.first() {
                // `intranet.com` answers with a private address, which the
                // post-answer inspection (rebinding shield) must catch.
                let ip = if question.name().to_ascii() == "intranet.com." {
                    std::net::Ipv4Addr::new(10, 0, 0, 1)
                } else {
                    std::net::Ipv4Addr::new(93, 184, 216, 34)
                };
                // `big-answer.com` answers with 60 records: larger than the
                // 512 bytes a client without EDNS accepts over UDP.
                let count = if question.name().to_ascii() == "big-answer.com." {
                    60
                } else {
                    1
                };
                for idx in 0..count {
                    let ip = if count == 1 {
                        ip
                    } else {
                        std::net::Ipv4Addr::new(93, 184, 216, idx)
                    };
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        300,
                        RData::A(A(ip)),
                    ));
                }
            }
            response
                .to_vec()
                .map_err(|e| std::io::Error::other(e.to_string()))
        }
    }

    fn query_bytes(domain: &str) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(
            Name::from_ascii(format!("{domain}.")).unwrap(),
            RecordType::A,
        ));
        msg.to_vec().unwrap()
    }

    /// Run one query through `handle_query`; return the response rcode and
    /// how many upstream calls it caused.
    async fn run_query(domain: &str) -> (ResponseCode, usize) {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let before = UPSTREAM_CALLS.load(Ordering::SeqCst);
        handle_query(server, query_bytes(domain), client.local_addr().unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("a response must be sent")
            .unwrap();
        let response = Message::from_vec(&buf[..len]).unwrap();
        let calls = UPSTREAM_CALLS.load(Ordering::SeqCst) - before;
        (response.metadata.response_code, calls)
    }

    /// Tunnel-like name the pipeline forwards but that already scores
    /// before upstream: 61 characters crosses the long-domain mark while
    /// staying within the structural length and depth limits.
    fn tunnel_name() -> String {
        format!("{}.tunnel.com", "a".repeat(50))
    }

    /// Install an engine whitelisting `whitelist` and a config whose DGA
    /// heuristics are off (these tests are about the score gate, not about
    /// which names the heuristics flag). Returns the pre-upstream score of
    /// `name` with the pipeline action, measured with the maximum threshold
    /// because scoring stops counting once the threshold is reached.
    fn install_policy(whitelist: &[&str], name: &str) -> (u8, Action) {
        CURRENT_ENGINE.store(Arc::new(create_test_engine(&[], whitelist, &[])));
        let mut config = Config::default();
        config.security.intelligence.enabled = false;
        config.security.scoring.blocking_threshold = u8::MAX;
        CONFIG.store(Arc::new(config));
        let _ = UPSTREAM_RESOLVER.get_or_init(|| Arc::new(CountingResolver));
        let measured = crate::resolve::resolve_with_score(name);
        (measured.score.total, measured.action)
    }

    fn set_blocking_threshold(threshold: u8) {
        let mut config = (*CONFIG.load_full()).clone();
        config.security.scoring.blocking_threshold = threshold;
        CONFIG.store(Arc::new(config));
    }

    #[test]
    fn over_threshold_query_never_reaches_upstream() {
        run_with_globals(async {
            let name = tunnel_name();
            let (score, action) = install_policy(&[], &name);
            assert!(matches!(action, Action::ProxyToUpstream), "got {action:?}");
            assert!(score > 0);
            set_blocking_threshold(score);
            let (rcode, calls) = run_query(&name).await;
            assert_eq!(rcode, ResponseCode::NXDomain);
            assert_eq!(calls, 0, "the query itself must not leave the resolver");
        });
    }

    #[test]
    fn below_threshold_query_is_forwarded() {
        run_with_globals(async {
            let (score, _) = install_policy(&[], &tunnel_name());
            set_blocking_threshold(score);
            let (rcode, calls) = run_query("clean-domain.com").await;
            assert_eq!(rcode, ResponseCode::NoError);
            assert_eq!(calls, 1);
        });
    }

    #[test]
    fn whitelisted_query_over_threshold_is_blocked_before_upstream_too() {
        // Same outcome as the post-answer check always gave a whitelisted
        // name over the threshold, minus the upstream round trip.
        run_with_globals(async {
            let name = tunnel_name();
            let (score, action) = install_policy(&[&name], &name);
            assert!(matches!(action, Action::Allow), "got {action:?}");
            set_blocking_threshold(score);
            let (rcode, calls) = run_query(&name).await;
            assert_eq!(rcode, ResponseCode::NXDomain);
            assert_eq!(calls, 0);
        });
    }

    #[test]
    fn answer_inspection_still_blocks_after_upstream() {
        // The second check keeps its job: signals only visible in the
        // answer (here a private address) still block the response.
        run_with_globals(async {
            let (score, action) = install_policy(&[], "intranet.com");
            assert!(matches!(action, Action::ProxyToUpstream), "got {action:?}");
            // Only the answer can push it over.
            set_blocking_threshold(score + 1);
            let (rcode, calls) = run_query("intranet.com").await;
            assert_eq!(rcode, ResponseCode::NXDomain);
            assert_eq!(calls, 1);
        });
    }

    // ---- packet screening in handle_query (review E3) ----

    /// Feed raw `bytes` to `handle_query`; return the reply, if any, and
    /// how many upstream calls it caused.
    async fn run_raw(bytes: Vec<u8>) -> (Option<Vec<u8>>, usize) {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let before = UPSTREAM_CALLS.load(Ordering::SeqCst);
        handle_query(server, bytes, client.local_addr().unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 4096];
        let reply = tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
            .await
            .ok()
            .map(|received| buf[..received.unwrap().0].to_vec());
        (reply, UPSTREAM_CALLS.load(Ordering::SeqCst) - before)
    }

    fn response_bytes(domain: &str) -> Vec<u8> {
        let mut msg = Message::from_vec(&query_bytes(domain)).unwrap();
        msg.metadata.message_type = MessageType::Response;
        msg.add_answer(Record::from_rdata(
            Name::from_ascii(format!("{domain}.")).unwrap(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(93, 184, 216, 34))),
        ));
        msg.to_vec().unwrap()
    }

    #[test]
    fn response_packet_is_never_answered_nor_forwarded() {
        // A forged response whose source is another resolver (or dgaard
        // itself) must not start a reflection loop.
        run_with_globals(async {
            install_policy(&[], "clean-domain.com");
            let (reply, calls) = run_raw(response_bytes("clean-domain.com")).await;
            assert!(reply.is_none(), "a response must never be answered");
            assert_eq!(calls, 0);
        });
    }

    #[test]
    fn notify_gets_one_notimp_and_the_loop_stops() {
        run_with_globals(async {
            install_policy(&[], "clean-domain.com");
            let mut notify = Message::from_vec(&query_bytes("clean-domain.com")).unwrap();
            notify.metadata.op_code = hickory_resolver::proto::op::OpCode::Notify;
            let (reply, calls) = run_raw(notify.to_vec().unwrap()).await;
            let reply = reply.expect("a NOTIMP is sent once");
            let parsed = Message::from_vec(&reply).unwrap();
            assert_eq!(parsed.metadata.response_code, ResponseCode::NotImp);
            assert_eq!(calls, 0);

            // The NOTIMP bounced back (spoofed source) is dropped.
            let (bounced, calls) = run_raw(reply).await;
            assert!(bounced.is_none());
            assert_eq!(calls, 0);
        });
    }

    // ---- UDP size limit and TCP ----

    fn query_with_edns(domain: &str, payload: Option<u16>) -> Vec<u8> {
        let mut msg = Message::from_vec(&query_bytes(domain)).unwrap();
        if let Some(size) = payload {
            let mut edns = hickory_resolver::proto::op::Edns::new();
            edns.set_max_payload(size);
            msg.set_edns(edns);
        }
        msg.to_vec().unwrap()
    }

    /// Policy allowing many answer records (the answer-count heuristic is
    /// not what these tests are about).
    fn install_big_answer_policy() {
        install_policy(&[], "big-answer.com");
        let mut config = (*CONFIG.load_full()).clone();
        config.security.structure.max_answers_per_query = 200;
        CONFIG.store(Arc::new(config));
    }

    #[test]
    fn big_udp_answer_is_truncated_for_a_512_byte_client() {
        run_with_globals(async {
            install_big_answer_policy();
            let (reply, calls) = run_raw(query_with_edns("big-answer.com", None)).await;
            let reply = reply.expect("a reply");
            assert!(reply.len() <= 512, "{} bytes", reply.len());
            let parsed = Message::from_vec(&reply).unwrap();
            assert!(parsed.metadata.truncation, "TC=1: retry over TCP");
            assert!(parsed.answers.is_empty());
            assert_eq!(parsed.queries.len(), 1);
            assert_eq!(calls, 1);
        });
    }

    #[test]
    fn big_udp_answer_fits_an_edns_client() {
        run_with_globals(async {
            install_big_answer_policy();
            let (reply, _) = run_raw(query_with_edns("big-answer.com", Some(4096))).await;
            let parsed = Message::from_vec(&reply.unwrap()).unwrap();
            assert!(!parsed.metadata.truncation);
            assert_eq!(parsed.answers.len(), 60);
        });
    }

    #[test]
    fn tcp_answers_are_never_truncated() {
        run_with_globals(async {
            install_big_answer_policy();
            let peer: std::net::SocketAddr = "127.0.0.1:5353".parse().unwrap();
            let reply = answer_query(
                &query_with_edns("big-answer.com", None),
                peer,
                Transport::Tcp,
            )
            .await
            .unwrap();
            let parsed = Message::from_vec(&reply).unwrap();
            assert!(!parsed.metadata.truncation);
            assert_eq!(parsed.answers.len(), 60);
        });
    }

    #[test]
    fn cache_hit_is_truncated_for_a_smaller_client() {
        // Cached for an EDNS-4096 client, served to a 512-byte one.
        run_with_globals(async {
            install_big_answer_policy();
            let cache =
                crate::RESPONSE_CACHE.get_or_init(|| crate::cache::ResponseCache::new(1024));
            cache.remove("big-answer.com", 1);

            let (first, calls) = run_raw(query_with_edns("big-answer.com", Some(4096))).await;
            assert_eq!(
                Message::from_vec(&first.unwrap()).unwrap().answers.len(),
                60
            );
            assert_eq!(calls, 1);

            let (second, calls) = run_raw(query_with_edns("big-answer.com", None)).await;
            assert_eq!(calls, 0, "served from the cache");
            let second = second.unwrap();
            assert!(second.len() <= 512);
            assert!(Message::from_vec(&second).unwrap().metadata.truncation);
        });
    }
}
