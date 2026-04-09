mod packet;
mod upstream;

pub(crate) use packet::InspectedAnswer;

use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::dns::packet::DnsPacket;
use crate::dns::upstream::forward_to_upstream;
use crate::model::{Action, StatAction, StatBlockReason};
use crate::resolve::{check_qtype, resolve};
use crate::{STATS_COUNTERS, STATS_SENDER};

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
    let action = resolve(&dns_packet.domain);

    // 3. Process the action and determine stat action
    let (response, stat_action) = match &action {
        Action::Allow => {
            STATS_COUNTERS.increment_allowed();
            // Forward to upstream DNS server
            let resp = match forward_to_upstream(&packet).await {
                Ok(upstream_response) => upstream_response,
                Err(_) => DnsPacket::build_servfail_response(&dns_packet.message),
            };
            (resp, Some(StatAction::Allowed))
        }
        Action::ProxyToUpstream => {
            STATS_COUNTERS.increment_proxied();
            let resp = match forward_to_upstream(&packet).await {
                Ok(upstream_response) => upstream_response,
                Err(_) => DnsPacket::build_servfail_response(&dns_packet.message),
            };
            (resp, Some(StatAction::Proxied))
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
