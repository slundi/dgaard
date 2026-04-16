mod packet;
mod upstream;

pub(crate) use packet::InspectedAnswer;

use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::config::ScoringConfig;
use crate::dns::packet::DnsPacket;
use crate::dns::upstream::forward_to_upstream;
use crate::model::{Action, StatAction, StatBlockReason, SuspicionScore};
use crate::resolve::{check_qtype, resolve_with_score, score_answer};
use crate::{CONFIG, STATS_COUNTERS, STATS_SENDER};

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
            .unwrap_or(StatBlockReason::Suspicious)
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
/// 2. Runs the domain through the resolve pipeline
/// 3. Either blocks the query (NXDOMAIN) or forwards to upstream
/// 4. Sends the response back to the client
/// 5. Emits stats events for telemetry
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

    // 2a. QType Warden: block forbidden query types before domain resolution.
    //     This is the cheapest check — a u16 lookup — so it runs first.
    if let Some(reason) = check_qtype(dns_packet.qtype) {
        STATS_COUNTERS.increment_blocked();
        let stat_reason = StatBlockReason::from(&reason);
        let response = DnsPacket::build_nxdomain_response(&dns_packet.message);
        socket.send_to(&response, peer).await?;
        if let Some(sender) = STATS_SENDER.get() {
            sender.send_event(&dns_packet.domain, peer, StatAction::Blocked(stat_reason));
        }
        return Ok(());
    }

    // 2b. Run domain through the filter pipeline
    let resolve_result = resolve_with_score(&dns_packet.domain);
    let action = resolve_result.action;
    let mut score = resolve_result.score;

    // 3. Process the action and determine stat action
    let scoring = &CONFIG.load();
    let scoring = &scoring.security.scoring;
    let (response, stat_action) = match &action {
        Action::Allow => {
            match forward_to_upstream(&packet).await {
                Ok(upstream_bytes) => {
                    // DPI: score the upstream answer; block if it crosses the configured threshold
                    if let Some(answer) = InspectedAnswer::from_response(&upstream_bytes) {
                        score_answer(&mut score, &answer);
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
                        STATS_COUNTERS.increment_allowed();
                        (upstream_bytes, Some(stat_action))
                    }
                }
                Err(_) => {
                    STATS_COUNTERS.increment_allowed();
                    (
                        DnsPacket::build_servfail_response(&dns_packet.message),
                        Some(StatAction::Allowed),
                    )
                }
            }
        }
        Action::ProxyToUpstream => {
            match forward_to_upstream(&packet).await {
                Ok(upstream_bytes) => {
                    // DPI: score the upstream answer; block if it crosses the configured threshold
                    if let Some(answer) = InspectedAnswer::from_response(&upstream_bytes) {
                        score_answer(&mut score, &answer);
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
                        STATS_COUNTERS.increment_proxied();
                        (upstream_bytes, Some(stat_action))
                    }
                }
                Err(_) => {
                    STATS_COUNTERS.increment_proxied();
                    (
                        DnsPacket::build_servfail_response(&dns_packet.message),
                        Some(StatAction::Proxied),
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
            (
                DnsPacket::build_nxdomain_response(&dns_packet.message),
                None, // Don't log drops
            )
        }
        Action::LocalResolve(_ip) | Action::Respond(_ip) | Action::Redirect(_ip) => {
            STATS_COUNTERS.increment_proxied();
            // TODO: Build response with the provided IP address
            // For now, proxy to upstream as fallback
            let resp = match forward_to_upstream(&packet).await {
                Ok(upstream_response) => upstream_response,
                Err(_) => DnsPacket::build_servfail_response(&dns_packet.message),
            };
            (resp, Some(StatAction::Proxied))
        }
        Action::InternalRedirect(_) => {
            STATS_COUNTERS.increment_blocked();
            // TODO: Implement internal redirect logic
            (
                DnsPacket::build_nxdomain_response(&dns_packet.message),
                None,
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
