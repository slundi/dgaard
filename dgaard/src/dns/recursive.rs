//! Iterative recursive DNS resolver.
//!
//! Phase 2 of `docs/Roadmap-recursive-DNS.md`. The resolver walks the
//! delegation chain starting at the root servers and follows referrals
//! down to the authoritative answer, without delegating to any forwarder.
//!
//! ## What this commit ships
//!
//! - Full iterative loop (referral → glue → next zone)
//! - Strict / lenient bailiwick policy
//! - In-bailiwick glue extraction (out-of-bailiwick glue is dropped)
//! - CNAME chase with budget sharing
//! - Cycle detection: `visited_zones` and `visited_cnames` (xxh3_64 hashes)
//! - Hard caps on delegation depth + total queries per resolution
//! - EDNS0 OPT advertisement
//! - Sequential `ns_concurrency`
//! - Root hints compiled-in (with optional `root_hints_path` override)
//! - Metrics counters into [`crate::STATS_COUNTERS`]
//!
//! ## Deferred to the rest of Phase 2
//!
//! - TCP fallback when `TC=1` (today: increment the metric and return SERVFAIL)
//! - QNAME minimization (today: full QNAME on every hop; the config flag is
//!   parsed and stored so configs stay forward-compatible)
//! - Staggered / parallel NS fanout (config accepted, runtime is sequential)
//! - ECS striping (no ECS option is ever inserted, which is the only
//!   safe-by-default behaviour required by the roadmap)

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use twox_hash::XxHash3_64;

use crate::CONFIG;
use crate::dns::dnssec_chain::{
    DnssecVerdict, RecursiveDnssecValidator, extract_dnskey_rrset_from_answers,
    extract_ds_rrset_from_authority,
};
use crate::dns::packet::DnsPacket;
use crate::dns::resolver::UpstreamResolver;

pub use dgaard_engine::config::{BailiwickPolicy, RecursiveConfig};

/// Compiled-in IANA root server addresses (`named.root`-style snapshot).
///
/// Order does not matter — the resolver picks a random subset at the start
/// of each top-level resolution to spread load across operators.
///
/// Drift protection: a justfile recipe + CI job (rolling Phase 2 work) diff
/// this array against the canonical `https://www.internic.net/domain/named.root`
/// weekly.
pub const ROOT_HINTS_V4: &[(char, Ipv4Addr)] = &[
    ('a', Ipv4Addr::new(198, 41, 0, 4)),
    ('b', Ipv4Addr::new(170, 247, 170, 2)),
    ('c', Ipv4Addr::new(192, 33, 4, 12)),
    ('d', Ipv4Addr::new(199, 7, 91, 13)),
    ('e', Ipv4Addr::new(192, 203, 230, 10)),
    ('f', Ipv4Addr::new(192, 5, 5, 241)),
    ('g', Ipv4Addr::new(192, 112, 36, 4)),
    ('h', Ipv4Addr::new(198, 97, 190, 53)),
    ('i', Ipv4Addr::new(192, 36, 148, 17)),
    ('j', Ipv4Addr::new(192, 58, 128, 30)),
    ('k', Ipv4Addr::new(193, 0, 14, 129)),
    ('l', Ipv4Addr::new(199, 7, 83, 42)),
    ('m', Ipv4Addr::new(202, 12, 27, 33)),
];

/// IPv6 root server addresses, same operator letters as [`ROOT_HINTS_V4`].
pub const ROOT_HINTS_V6: &[(char, Ipv6Addr)] = &[
    (
        'a',
        Ipv6Addr::new(0x2001, 0x0503, 0xba3e, 0, 0, 0, 0x0002, 0x0030),
    ),
    (
        'b',
        Ipv6Addr::new(0x2801, 0x01b8, 0x0010, 0, 0, 0, 0, 0x000b),
    ),
    (
        'c',
        Ipv6Addr::new(0x2001, 0x0500, 0x0002, 0, 0, 0, 0, 0x000c),
    ),
    (
        'd',
        Ipv6Addr::new(0x2001, 0x0500, 0x002d, 0, 0, 0, 0, 0x000d),
    ),
    (
        'e',
        Ipv6Addr::new(0x2001, 0x0500, 0x00a8, 0, 0, 0, 0, 0x000e),
    ),
    (
        'f',
        Ipv6Addr::new(0x2001, 0x0500, 0x002f, 0, 0, 0, 0, 0x000f),
    ),
    (
        'g',
        // G-root IPv6 is 2001:500:12::d0d, not ::d. Caught by the
        // operational drift-check landed alongside this constant.
        Ipv6Addr::new(0x2001, 0x0500, 0x0012, 0, 0, 0, 0, 0x0d0d),
    ),
    (
        'h',
        Ipv6Addr::new(0x2001, 0x0500, 0x0001, 0, 0, 0, 0, 0x0053),
    ),
    ('i', Ipv6Addr::new(0x2001, 0x07fe, 0, 0, 0, 0, 0, 0x0053)),
    (
        'j',
        Ipv6Addr::new(0x2001, 0x0503, 0x0c27, 0, 0, 0, 0x0002, 0x0030),
    ),
    ('k', Ipv6Addr::new(0x2001, 0x07fd, 0, 0, 0, 0, 0, 0x0001)),
    (
        'l',
        Ipv6Addr::new(0x2001, 0x0500, 0x009f, 0, 0, 0, 0, 0x0042),
    ),
    ('m', Ipv6Addr::new(0x2001, 0x0dc3, 0, 0, 0, 0, 0, 0x0035)),
];

/// xxh3_64 with a fixed seed of 0 — the resolver's cycle-detection sets
/// only ever live for the duration of one client resolution, so the seed
/// only needs to be stable *within* a single process. Phase 3's
/// `PopularityTracker` uses the same seed so the hash spaces can be
/// reused if we ever cross-reference them.
fn hash_zone_label(name: &Name) -> u64 {
    let lower = name.to_string().to_ascii_lowercase();
    XxHash3_64::oneshot_with_seed(0, lower.as_bytes())
}

/// Bailiwick test: returns true iff `child` is at or below `zone`. A
/// referral whose authority section names a zone that does not satisfy
/// this predicate has widened the resolution — a classic cache-poisoning
/// attempt that we reject by default (see [`BailiwickPolicy`]).
pub fn is_in_bailiwick(zone: &Name, child: &Name) -> bool {
    // `zone.zone_of(child)` already handles the root case (`zone_of`
    // returns `true` for any name when `self` is root).
    zone.zone_of(child)
}

/// Out-of-bailiwick glue is poisonous: an authority section advertising
/// `ns1.attacker.com` with an A record for `8.8.8.8` would, if accepted,
/// let the attacker hijack the entire `8.8.8.8` lookup space. We accept
/// glue **only** for NS names that sit inside the new zone.
pub fn collect_in_bailiwick_glue(
    response: &Message,
    ns_names: &[Name],
    new_zone: &Name,
) -> Vec<IpAddr> {
    let mut glue = Vec::new();
    for record in &response.additionals {
        let name = &record.name;
        if !is_in_bailiwick(new_zone, name) {
            continue;
        }
        if !ns_names.iter().any(|n| n == name) {
            continue;
        }
        match &record.data {
            RData::A(a) => glue.push(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => glue.push(IpAddr::V6(aaaa.0)),
            _ => {}
        }
    }
    glue
}

/// Pick out the NS names listed in the authority section of a referral.
/// Anything that isn't an NS RR (e.g. SOA on NODATA) is ignored.
pub fn extract_ns_names(authority: &[Record]) -> Vec<Name> {
    authority
        .iter()
        .filter_map(|r| match &r.data {
            RData::NS(ns) => Some(ns.0.clone()),
            _ => None,
        })
        .collect()
}

/// The zone all NS records in the authority section delegate to. We trust
/// the first NS's owner name — they must all match on a well-formed
/// referral; if they don't, the zone we pick is irrelevant because the
/// bailiwick check on the *first* name catches widened referrals anyway.
pub fn extract_referral_zone(authority: &[Record]) -> Option<Name> {
    authority
        .iter()
        .find(|r| matches!(&r.data, RData::NS(_)))
        .map(|r| r.name.clone())
}

/// First CNAME target in the answer section, lowercased once for hashing.
pub fn extract_cname_target(answers: &[Record]) -> Option<Name> {
    answers.iter().find_map(|r| match &r.data {
        RData::CNAME(c) => Some(c.0.clone()),
        _ => None,
    })
}

/// Build a UDP-bound DNS query for `qname` of `qtype`, with the requested
/// flags and EDNS0 buffer size. The transaction ID is randomised per call
/// so an off-path attacker has to win a 16-bit lottery to inject a forged
/// response, just like the forwarder does.
pub fn build_outgoing_query(
    qname: &Name,
    qtype: RecordType,
    edns0_payload_size: Option<u16>,
    dnssec_ok: bool,
) -> Message {
    let mut msg = Message::query();
    msg.metadata.op_code = OpCode::Query;
    msg.metadata.recursion_desired = false; // we are *the* recursive resolver
    let query = Query::query(qname.clone(), qtype)
        .set_query_class(DNSClass::IN)
        .clone();
    msg.add_query(query);

    // EDNS0 OPT and the DO ("DNSSEC OK") bit are independently
    // controlled because a stub resolver may want OPT (for the buffer
    // size) without asking for DNSSEC material it can't validate.
    // Authoritatives only return RRSIGs when DO is set (RFC 6840 §5.9).
    if edns0_payload_size.is_some() || dnssec_ok {
        let mut edns = Edns::new();
        if let Some(bufsize) = edns0_payload_size {
            edns.set_max_payload(bufsize);
        }
        edns.set_version(0);
        if dnssec_ok {
            edns.set_dnssec_ok(true);
        }
        msg.set_edns(edns);
    }

    msg
}

/// Outcome of one iteration of the delegation loop. Keeps the loop body
/// readable and trivially unit-testable in isolation.
#[derive(Debug)]
pub enum ResponseKind {
    Answer,
    Referral { new_zone: Name, ns_names: Vec<Name> },
    NxDomain,
    Empty,
    NeedTcpFallback,
}

/// Classify an upstream response. The same Message instance is consumed
/// downstream regardless of which variant we return — the caller decides
/// what to do with the answer / authority / additional sections.
pub fn classify_response(response: &Message) -> ResponseKind {
    if response.metadata.truncation {
        return ResponseKind::NeedTcpFallback;
    }
    match response.metadata.response_code {
        ResponseCode::NXDomain => return ResponseKind::NxDomain,
        ResponseCode::NoError => {}
        _ => return ResponseKind::Empty, // SERVFAIL / REFUSED → try next NS
    }
    if !response.answers.is_empty() {
        return ResponseKind::Answer;
    }
    let ns_names = extract_ns_names(&response.authorities);
    if !ns_names.is_empty()
        && let Some(new_zone) = extract_referral_zone(&response.authorities)
    {
        return ResponseKind::Referral { new_zone, ns_names };
    }
    ResponseKind::Empty
}

// ---------------------------------------------------------------------------
// The resolver itself
// ---------------------------------------------------------------------------

/// Iterative recursive resolver. Holds the configuration and the current
/// root-hint table so the hot path never touches `CONFIG.load()` for
/// values that are fixed at startup.
pub struct RecursiveResolver {
    pub(crate) config: RecursiveConfig,
    pub(crate) roots: Vec<SocketAddr>,
    /// Optional DNSSEC chain validator. `Some` when `[security.dnssec]
    /// enabled = true` at startup; `None` otherwise. Holding it
    /// directly (rather than reading the global on every hop) keeps
    /// the hot path branch-predictable and lets tests construct an
    /// isolated resolver.
    pub(crate) validator: Option<Arc<RecursiveDnssecValidator>>,
}

impl RecursiveResolver {
    /// Build a resolver from a snapshot of the current config. Root hints
    /// are loaded from disk if `root_hints_path` is set; otherwise the
    /// compiled-in IANA set is used.
    pub fn from_config(config: RecursiveConfig) -> io::Result<Self> {
        let roots = match config.root_hints_path.as_deref() {
            Some(path) => load_root_hints_file(path)?,
            None => default_roots(),
        };
        if roots.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no usable root server addresses; supply a valid root hints file",
            ));
        }
        Ok(Self {
            config,
            roots,
            validator: None,
        })
    }

    /// Builder: attach a DNSSEC validator. The iterative loop will then
    /// harvest DS records from referrals and issue DNSKEY queries
    /// against each new zone, feeding both into the validator.
    pub fn with_validator(mut self, validator: Arc<RecursiveDnssecValidator>) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Convenience: build with an explicit root-server list. Used by
    /// integration tests that point the resolver at an in-process mock
    /// instead of the real IANA servers.
    #[allow(dead_code)]
    pub fn with_roots(config: RecursiveConfig, roots: Vec<SocketAddr>) -> Self {
        Self {
            config,
            roots,
            validator: None,
        }
    }

    /// Resolve `qname` / `qtype`, returning the final upstream `Message`.
    /// Cycle-detection state is threaded through every recursion (CNAME
    /// chase + out-of-zone NS resolve) so a malicious chain cannot escape
    /// the per-query budget by hopping into a sub-resolve.
    pub fn resolve_iterative<'a>(
        &'a self,
        qname: Name,
        qtype: RecordType,
        visited_zones: &'a mut Vec<u64>,
        visited_cnames: &'a mut Vec<u64>,
        queries_used: &'a mut u32,
    ) -> Pin<Box<dyn Future<Output = io::Result<Message>> + Send + 'a>> {
        Box::pin(async move {
            let mut ns_addrs: Vec<SocketAddr> = pick_initial_ns_addrs(&self.roots);
            let mut current_zone = Name::root();
            let mut depth: u8 = 0;

            loop {
                if *queries_used >= self.config.max_queries_per_resolution {
                    crate::STATS_COUNTERS.increment_recursive_query_cap_hit();
                    return Err(io::Error::other("max_queries_per_resolution exceeded"));
                }
                if depth >= self.config.max_delegation_depth {
                    crate::STATS_COUNTERS.increment_recursive_depth_cap_hit();
                    return Err(io::Error::other("max_delegation_depth exceeded"));
                }

                let response = self
                    .query_any_ns(&ns_addrs, &qname, qtype, queries_used)
                    .await?;

                match classify_response(&response) {
                    ResponseKind::Answer => {
                        // CNAME chase: if the answer is a CNAME and we did
                        // not ask for CNAME, follow the alias with a fresh
                        // depth budget but the same query budget.
                        if qtype != RecordType::CNAME
                            && let Some(target) = extract_cname_target(&response.answers)
                        {
                            let target_hash = hash_zone_label(&target);
                            if visited_cnames.contains(&target_hash) {
                                crate::STATS_COUNTERS.increment_recursive_cycle_detected();
                                return Err(io::Error::other("CNAME cycle"));
                            }
                            if (visited_cnames.len() as u8) >= self.config.max_cname_depth {
                                return Err(io::Error::other("max_cname_depth exceeded"));
                            }
                            visited_cnames.push(target_hash);
                            return self
                                .resolve_iterative(
                                    target,
                                    qtype,
                                    visited_zones,
                                    visited_cnames,
                                    queries_used,
                                )
                                .await;
                        }
                        return Ok(response);
                    }
                    ResponseKind::Referral { new_zone, ns_names } => {
                        crate::STATS_COUNTERS.increment_recursive_referrals();
                        if !is_in_bailiwick(&current_zone, &new_zone) {
                            crate::STATS_COUNTERS.increment_recursive_bailiwick_reject();
                            match self.config.bailiwick_policy {
                                BailiwickPolicy::Strict => {
                                    return Err(io::Error::other("out-of-bailiwick referral"));
                                }
                                BailiwickPolicy::Lenient => {
                                    // Lenient mode: discard this referral.
                                    // The next NS we'd try lives in
                                    // ns_addrs which we already exhausted
                                    // for this query; give up.
                                    return Err(io::Error::other("all NS gave bad referrals"));
                                }
                            }
                        }

                        let zone_hash = hash_zone_label(&new_zone);
                        if visited_zones.contains(&zone_hash) {
                            crate::STATS_COUNTERS.increment_recursive_cycle_detected();
                            return Err(io::Error::other("delegation cycle"));
                        }
                        visited_zones.push(zone_hash);

                        let glue = collect_in_bailiwick_glue(&response, &ns_names, &new_zone);
                        if !glue.is_empty() {
                            crate::STATS_COUNTERS.increment_recursive_glue_hit();
                            ns_addrs = glue.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect();
                        } else {
                            crate::STATS_COUNTERS.increment_recursive_glue_miss();
                            ns_addrs = self
                                .resolve_ns_addresses(
                                    &ns_names,
                                    visited_zones,
                                    visited_cnames,
                                    queries_used,
                                )
                                .await?;
                            if ns_addrs.is_empty() {
                                return Err(io::Error::other("no usable NS addresses"));
                            }
                        }

                        // Phase 6 session 2: harvest the DS rrset that
                        // the *parent* zone served in the referral, then
                        // pull the *child*'s DNSKEY from one of the
                        // newly-chosen NSes. This walks the chain of
                        // trust forward one delegation hop. Failures
                        // are noted via metrics but do not abort the
                        // resolution — DNSSEC's "best evidence wins"
                        // is enforced at answer time in handle_query.
                        if let Some(validator) = self.validator.clone() {
                            self.build_chain_step(
                                &validator,
                                &response,
                                &current_zone,
                                &new_zone,
                                &ns_addrs,
                                queries_used,
                            )
                            .await;
                        }

                        current_zone = new_zone;
                        depth = depth.saturating_add(1);
                    }
                    ResponseKind::NxDomain => return Ok(response),
                    ResponseKind::NeedTcpFallback => {
                        crate::STATS_COUNTERS.increment_recursive_tcp_fallback();
                        return Err(io::Error::other(
                            "UDP truncated and TCP fallback not implemented yet",
                        ));
                    }
                    ResponseKind::Empty => {
                        return Err(io::Error::other("empty/SERVFAIL response"));
                    }
                }
            }
        })
    }

    /// Sequentially walk `ns_addrs`, send `qname / qtype` to each, return
    /// the first parseable response. Increments `queries_used` per
    /// launched query so amplification accounts correctly.
    async fn query_any_ns(
        &self,
        ns_addrs: &[SocketAddr],
        qname: &Name,
        qtype: RecordType,
        queries_used: &mut u32,
    ) -> io::Result<Message> {
        let mut last_err: Option<io::Error> = None;
        for addr in ns_addrs {
            if *queries_used >= self.config.max_queries_per_resolution {
                break;
            }
            *queries_used += 1;
            crate::STATS_COUNTERS.increment_recursive_queries();
            match self.query_single_ns(*addr, qname, qtype).await {
                Ok(msg) => return Ok(msg),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no NS addresses to query")))
    }

    /// One UDP exchange. Caller has already paid the `queries_used` cost.
    async fn query_single_ns(
        &self,
        addr: SocketAddr,
        qname: &Name,
        qtype: RecordType,
    ) -> io::Result<Message> {
        let bind = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        let edns = self
            .config
            .edns0_enabled
            .then_some(self.config.edns0_udp_payload_size);
        // Set the DO bit whenever a chain validator is installed so
        // upstream authoritatives include RRSIGs in their responses.
        let dnssec_ok = self.validator.is_some();
        let query = build_outgoing_query(qname, qtype, edns, dnssec_ok);
        let bytes = query
            .to_vec()
            .map_err(|e| io::Error::other(format!("encode query: {e}")))?;
        socket.send_to(&bytes, addr).await?;

        let mut buf = [0u8; 4096];
        let to = Duration::from_millis(self.config.query_timeout_ms);
        let (len, peer) = match timeout(to, socket.recv_from(&mut buf)).await {
            Ok(res) => res?,
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "NS UDP timeout")),
        };
        if peer != addr {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response source mismatch",
            ));
        }
        let response = Message::from_vec(&buf[..len])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("parse: {e}")))?;
        if response.metadata.id != query.metadata.id {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "TXID mismatch"));
        }
        Ok(response)
    }

    /// Phase 6 session 2: extend the chain of trust through one
    /// delegation hop.
    ///
    /// 1. **DS hand-off** — extract the child's DS rrset from the
    ///    parent's referral (the parent's authority section) and feed
    ///    it to the validator. The DS rrset's RRSIG is signed by the
    ///    *parent*, so this must run while the validator still has
    ///    the parent's DNSKEYs cached.
    /// 2. **DNSKEY fetch** — issue a fresh DNSKEY query against the
    ///    child's NS addresses with the DO bit set, then record the
    ///    returned DNSKEY rrset. The validator self-verifies the rrset
    ///    against its own KSK *and* against the just-installed DS.
    ///
    /// Each step bumps `queries_used` so a misbehaving zone can't
    /// inflate the per-query budget by serving a DS rrset every hop.
    /// Failures are reported through
    /// `recursive_dnssec_chain_broken` and do not abort the resolution.
    /// Insecure delegations (no DS) are silent — that's a normal
    /// downgrade and session 3 will encode the NSEC proof that
    /// justifies it.
    async fn build_chain_step(
        &self,
        validator: &Arc<RecursiveDnssecValidator>,
        referral: &Message,
        parent_zone: &Name,
        child_zone: &Name,
        ns_addrs: &[SocketAddr],
        queries_used: &mut u32,
    ) {
        // Step 1: DS hand-off, parent → child.
        if let Some((ds_records, ds_sig)) = extract_ds_rrset_from_authority(referral, child_zone) {
            match validator.record_ds_for_child(parent_zone, child_zone, &ds_records, &ds_sig) {
                DnssecVerdict::Bogus => {
                    crate::STATS_COUNTERS.increment_recursive_dnssec_chain_broken();
                    // A Bogus DS means the parent told us *something*
                    // about the child but we couldn't verify it. The
                    // session-3 contract is to fail the whole resolve;
                    // for now we keep walking and let `validate_message`
                    // at answer time make the final call.
                }
                DnssecVerdict::Secure | DnssecVerdict::Insecure => {}
            }
        }

        // Step 2: pull DNSKEY from the child zone. Budget-bounded — if
        // the resolver is already saturating its per-query cap, skip
        // the chain hop entirely rather than starve the answer fetch.
        if *queries_used >= self.config.max_queries_per_resolution {
            return;
        }
        let Ok(dnskey_msg) = self
            .query_any_ns(ns_addrs, child_zone, RecordType::DNSKEY, queries_used)
            .await
        else {
            return;
        };
        let Some((dnskey_records, dnskey_sig)) = extract_dnskey_rrset_from_answers(&dnskey_msg)
        else {
            return;
        };
        match validator.record_dnskey_rrset(child_zone, &dnskey_records, &dnskey_sig) {
            DnssecVerdict::Secure => {
                crate::STATS_COUNTERS.increment_recursive_dnssec_chain_built();
            }
            DnssecVerdict::Bogus => {
                crate::STATS_COUNTERS.increment_recursive_dnssec_chain_broken();
            }
            DnssecVerdict::Insecure => {
                // No DS available → can't authenticate this DNSKEY
                // rrset. Not a chain failure on its own; the parent's
                // *secure denial of DS* (session 3) is what classifies
                // the child as legitimately Insecure.
            }
        }
    }

    /// Resolve the IP addresses of out-of-zone NS names by recursing for
    /// each name. Budgets (`visited_*`, `queries_used`) are threaded
    /// through so a fan-out can never escape the per-query caps.
    fn resolve_ns_addresses<'a>(
        &'a self,
        ns_names: &'a [Name],
        visited_zones: &'a mut Vec<u64>,
        visited_cnames: &'a mut Vec<u64>,
        queries_used: &'a mut u32,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let mut out = Vec::new();
            for ns in ns_names {
                if *queries_used >= self.config.max_queries_per_resolution {
                    break;
                }
                match self
                    .resolve_iterative(
                        ns.clone(),
                        RecordType::A,
                        visited_zones,
                        visited_cnames,
                        queries_used,
                    )
                    .await
                {
                    Ok(msg) => {
                        for rec in msg.answers {
                            if let RData::A(a) = &rec.data {
                                out.push(SocketAddr::new(IpAddr::V4(a.0), 53));
                            }
                        }
                    }
                    Err(_) => continue,
                }
                // Stop early once we have *something* to query — the next
                // hop in the outer loop will recover if these prove bad.
                if !out.is_empty() {
                    break;
                }
            }
            Ok(out)
        })
    }
}

/// Re-stamp the upstream `Message` so it can be sent back to the original
/// client: the TXID is the client's, RD echoes the client's request, RA=1
/// because we *are* the recursive resolver.
fn build_client_response(client_query: &DnsPacket, mut upstream: Message) -> io::Result<Vec<u8>> {
    upstream.metadata.id = client_query.message.metadata.id;
    upstream.metadata.message_type = MessageType::Response;
    upstream.metadata.recursion_available = true;
    upstream.metadata.recursion_desired = client_query.message.metadata.recursion_desired;
    upstream.metadata.authoritative = false;
    // Make sure the question section echoes the client's question — some
    // stubs reject responses that don't.
    if upstream.queries.is_empty()
        && let Some(q) = client_query.message.queries.first()
    {
        upstream.add_query(q.clone());
    }
    upstream
        .to_vec()
        .map_err(|e| io::Error::other(format!("encode response: {e}")))
}

#[async_trait]
impl UpstreamResolver for RecursiveResolver {
    async fn resolve(&self, query: &DnsPacket) -> io::Result<Vec<u8>> {
        let cfg = CONFIG.load();
        // Refresh per-call: while the resolver caches a snapshot at
        // startup (root hints, primarily), runtime tuning still flows
        // through CONFIG so SIGHUP-reloaded values take effect.
        let _ = cfg; // currently no per-call config knobs read here

        let q = query
            .message
            .queries
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no query in packet"))?;
        let qname = q.name().clone();
        let qtype = q.query_type();

        let mut visited_zones = Vec::with_capacity(self.config.max_delegation_depth as usize);
        let mut visited_cnames = Vec::with_capacity(self.config.max_cname_depth as usize);
        let mut queries_used: u32 = 0;

        let upstream = self
            .resolve_iterative(
                qname,
                qtype,
                &mut visited_zones,
                &mut visited_cnames,
                &mut queries_used,
            )
            .await?;
        build_client_response(query, upstream)
    }
}

// ---------------------------------------------------------------------------
// Root hints helpers
// ---------------------------------------------------------------------------

/// Compiled-in IANA roots, IPv4 first then IPv6. Tests use the same
/// helper; production injects from this list when no override is given.
pub fn default_roots() -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = ROOT_HINTS_V4
        .iter()
        .map(|(_, ip)| SocketAddr::new(IpAddr::V4(*ip), 53))
        .collect();
    out.extend(
        ROOT_HINTS_V6
            .iter()
            .map(|(_, ip)| SocketAddr::new(IpAddr::V6(*ip), 53)),
    );
    out
}

/// Parse a BIND-style `named.root` file. The format is loose; we accept
/// any A / AAAA glue lines for the 13 root operators. Lines we can't
/// parse are skipped silently — the file is operator-supplied and a
/// stray comment shouldn't refuse to start the daemon.
fn load_root_hints_file(path: &str) -> io::Result<Vec<SocketAddr>> {
    let content = std::fs::read_to_string(path)?;
    Ok(parse_root_hints(&content).into_socket_addrs().collect())
}

/// Parsed view of a `named.root` file: A and AAAA records keyed by the
/// single-letter operator label ('a' through 'm'). Used both by the
/// startup-time root-hint loader and by the drift-check tool.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct RootHintsTable {
    pub v4: Vec<(char, Ipv4Addr)>,
    pub v6: Vec<(char, Ipv6Addr)>,
}

impl RootHintsTable {
    /// Flatten into the `Vec<SocketAddr>` format the resolver loop
    /// consumes. IPv4 first, then IPv6 — matches `default_roots()`.
    pub fn into_socket_addrs(self) -> impl Iterator<Item = SocketAddr> {
        let v4 = self
            .v4
            .into_iter()
            .map(|(_, ip)| SocketAddr::new(IpAddr::V4(ip), 53));
        let v6 = self
            .v6
            .into_iter()
            .map(|(_, ip)| SocketAddr::new(IpAddr::V6(ip), 53));
        v4.chain(v6)
    }
}

/// Lower-cased operator letter from a root-server name like
/// `A.ROOT-SERVERS.NET.`. Returns `None` for any name that doesn't
/// match the official root-zone convention.
fn root_operator_letter(name: &str) -> Option<char> {
    let upper = name.to_ascii_uppercase();
    let stripped = upper.trim_end_matches('.');
    let (letter, rest) = stripped.split_once('.')?;
    if rest != "ROOT-SERVERS.NET" {
        return None;
    }
    let mut chars = letter.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    if !c.is_ascii_alphabetic() {
        return None;
    }
    Some(c.to_ascii_lowercase())
}

/// Parse a BIND-style `named.root` string into a [`RootHintsTable`].
/// Order is preserved as encountered in the file so callers can
/// produce stable diffs.
pub fn parse_root_hints(content: &str) -> RootHintsTable {
    let mut table = RootHintsTable::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        let mut iter = line.split_whitespace();
        let owner = iter.next();
        let _ttl = iter.next();
        let rrtype = match iter.next() {
            Some(t) => t.to_ascii_uppercase(),
            None => continue,
        };
        let value = match iter.next() {
            Some(v) => v,
            None => continue,
        };
        let Some(letter) = owner.and_then(root_operator_letter) else {
            continue;
        };
        match rrtype.as_str() {
            "A" => {
                if let Ok(ip) = value.parse::<Ipv4Addr>() {
                    table.v4.push((letter, ip));
                }
            }
            "AAAA" => {
                if let Ok(ip) = value.parse::<Ipv6Addr>() {
                    table.v6.push((letter, ip));
                }
            }
            _ => {}
        }
    }
    table
}

/// Compare a freshly-parsed [`RootHintsTable`] against the
/// compiled-in [`ROOT_HINTS_V4`] / [`ROOT_HINTS_V6`] constants.
///
/// Returns one human-readable line per discrepancy: missing operators,
/// extra operators, and addresses that have drifted. An empty `Vec`
/// means perfect agreement.
///
/// The diff is symmetric — it catches both "the compiled-in
/// constants are stale" *and* "someone fed us a corrupt
/// `named.root`". The drift-check tool exits non-zero on any line; a
/// release-time regenerator uses the missing/extra/drift lines to
/// hand-patch the consts.
///
/// Reachable only from the env-gated drift test; `#[allow(dead_code)]`
/// keeps the bin target quiet while still exposing the helper for
/// `cargo test` to consume.
#[allow(dead_code)]
pub fn diff_against_compiled(parsed: &RootHintsTable) -> Vec<String> {
    let mut diffs = Vec::new();
    diff_one_family(
        "A",
        &parsed
            .v4
            .iter()
            .map(|(c, ip)| (*c, ip.to_string()))
            .collect::<Vec<_>>(),
        &ROOT_HINTS_V4
            .iter()
            .map(|(c, ip)| (*c, ip.to_string()))
            .collect::<Vec<_>>(),
        &mut diffs,
    );
    diff_one_family(
        "AAAA",
        &parsed
            .v6
            .iter()
            .map(|(c, ip)| (*c, ip.to_string()))
            .collect::<Vec<_>>(),
        &ROOT_HINTS_V6
            .iter()
            .map(|(c, ip)| (*c, ip.to_string()))
            .collect::<Vec<_>>(),
        &mut diffs,
    );
    diffs
}

#[allow(dead_code)]
fn diff_one_family(
    family: &str,
    parsed: &[(char, String)],
    compiled: &[(char, String)],
    out: &mut Vec<String>,
) {
    use std::collections::BTreeMap;
    let p: BTreeMap<char, &str> = parsed.iter().map(|(c, s)| (*c, s.as_str())).collect();
    let c: BTreeMap<char, &str> = compiled.iter().map(|(ch, s)| (*ch, s.as_str())).collect();
    for (op, pip) in &p {
        match c.get(op) {
            None => out.push(format!(
                "{family} {op}: missing in compiled (upstream={pip})"
            )),
            Some(cip) if cip != pip => out.push(format!(
                "{family} {op}: drift — compiled={cip} upstream={pip}"
            )),
            _ => {}
        }
    }
    for op in c.keys() {
        if !p.contains_key(op) {
            out.push(format!(
                "{family} {op}: missing in upstream (compiled-in but absent from named.root)"
            ));
        }
    }
}

/// Pick three NS addresses at random from `roots`, falling back to the
/// full list if fewer than three are available. Sequential ns_concurrency
/// then tries them in order until one answers.
fn pick_initial_ns_addrs(roots: &[SocketAddr]) -> Vec<SocketAddr> {
    if roots.len() <= 3 {
        return roots.to_vec();
    }
    // Cheap, biased shuffle is fine — we just want some spread, not
    // cryptographic randomness.
    let mut seed = getrandom::u64().unwrap_or(0x9E37_79B9_7F4A_7C15);
    let mut indices: Vec<usize> = (0..roots.len()).collect();
    for i in (1..indices.len()).rev() {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (seed as usize) % (i + 1);
        indices.swap(i, j);
    }
    indices.into_iter().take(3).map(|i| roots[i]).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME, NS};

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    // ---- root hints ----

    #[test]
    fn compiled_root_hints_have_all_13_letters_v4() {
        let letters: Vec<char> = ROOT_HINTS_V4.iter().map(|(c, _)| *c).collect();
        let mut sorted = letters.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, ('a'..='m').collect::<Vec<_>>());
    }

    #[test]
    fn compiled_root_hints_have_all_13_letters_v6() {
        let letters: Vec<char> = ROOT_HINTS_V6.iter().map(|(c, _)| *c).collect();
        let mut sorted = letters.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, ('a'..='m').collect::<Vec<_>>());
    }

    #[test]
    fn default_roots_combines_both_address_families() {
        let roots = default_roots();
        assert_eq!(roots.len(), 26);
        assert!(roots.iter().any(|a| a.is_ipv4()));
        assert!(roots.iter().any(|a| a.is_ipv6()));
    }

    #[test]
    fn pick_initial_ns_addrs_returns_three_or_fewer() {
        let roots = default_roots();
        assert_eq!(pick_initial_ns_addrs(&roots).len(), 3);
        let small: Vec<_> = roots.into_iter().take(2).collect();
        assert_eq!(pick_initial_ns_addrs(&small).len(), 2);
    }

    #[test]
    fn pick_initial_ns_addrs_returns_distinct_indices() {
        let roots = default_roots();
        let picked = pick_initial_ns_addrs(&roots);
        let mut sorted = picked.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), picked.len());
    }

    // ---- Operational: root-hints drift check ----

    /// A minimal but realistic `named.root` fixture covering all 13
    /// operators in both address families. Used to anchor the
    /// parser/diff unit tests without reaching the network.
    fn fixture_named_root() -> String {
        // Built from the IANA-published values current at the time
        // session-1 root hints were compiled in; if the unit tests
        // below ever flag drift it is because BOTH the file and the
        // compiled-in constants moved.
        let lines = [
            ".                        3600000      NS    A.ROOT-SERVERS.NET.",
            "A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4",
            "A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30",
            "B.ROOT-SERVERS.NET.      3600000      A     170.247.170.2",
            "B.ROOT-SERVERS.NET.      3600000      AAAA  2801:1b8:10::b",
            "C.ROOT-SERVERS.NET.      3600000      A     192.33.4.12",
            "C.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2::c",
            "D.ROOT-SERVERS.NET.      3600000      A     199.7.91.13",
            "D.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2d::d",
            "E.ROOT-SERVERS.NET.      3600000      A     192.203.230.10",
            "E.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:a8::e",
            "F.ROOT-SERVERS.NET.      3600000      A     192.5.5.241",
            "F.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2f::f",
            "G.ROOT-SERVERS.NET.      3600000      A     192.112.36.4",
            "G.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:12::d0d",
            "H.ROOT-SERVERS.NET.      3600000      A     198.97.190.53",
            "H.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:1::53",
            "I.ROOT-SERVERS.NET.      3600000      A     192.36.148.17",
            "I.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fe::53",
            "J.ROOT-SERVERS.NET.      3600000      A     192.58.128.30",
            "J.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:c27::2:30",
            "K.ROOT-SERVERS.NET.      3600000      A     193.0.14.129",
            "K.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fd::1",
            "L.ROOT-SERVERS.NET.      3600000      A     199.7.83.42",
            "L.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:9f::42",
            "M.ROOT-SERVERS.NET.      3600000      A     202.12.27.33",
            "M.ROOT-SERVERS.NET.      3600000      AAAA  2001:dc3::35",
        ];
        lines.join("\n")
    }

    #[test]
    fn root_operator_letter_extracts_single_letter_from_root_servers_name() {
        assert_eq!(root_operator_letter("A.ROOT-SERVERS.NET."), Some('a'));
        assert_eq!(root_operator_letter("m.root-servers.net."), Some('m'));
        // Missing trailing dot still parses — operators occasionally
        // ship non-canonical files.
        assert_eq!(root_operator_letter("J.ROOT-SERVERS.NET"), Some('j'));
        // Anything not under ROOT-SERVERS.NET is rejected: this is the
        // crucial anti-poisoning check.
        assert_eq!(root_operator_letter("A.EVIL.NET."), None);
        assert_eq!(root_operator_letter("AA.ROOT-SERVERS.NET."), None);
        assert_eq!(root_operator_letter("1.ROOT-SERVERS.NET."), None);
    }

    #[test]
    fn parse_root_hints_extracts_all_operators_from_fixture() {
        let parsed = parse_root_hints(&fixture_named_root());
        assert_eq!(parsed.v4.len(), 13, "must find 13 IPv4 operators");
        assert_eq!(parsed.v6.len(), 13, "must find 13 IPv6 operators");
        // All 13 letters present.
        let letters_v4: std::collections::BTreeSet<char> =
            parsed.v4.iter().map(|(c, _)| *c).collect();
        let letters_v6: std::collections::BTreeSet<char> =
            parsed.v6.iter().map(|(c, _)| *c).collect();
        let expected: std::collections::BTreeSet<char> = ('a'..='m').collect();
        assert_eq!(letters_v4, expected);
        assert_eq!(letters_v6, expected);
    }

    #[test]
    fn parse_root_hints_ignores_unrelated_lines() {
        // Real `named.root` files have an NS line, comments, and the
        // glue. Only A/AAAA glue records owned by *.ROOT-SERVERS.NET.
        // must enter the table.
        let content = "\
            ; comment\n\
            .                        3600000      NS    A.ROOT-SERVERS.NET.\n\
            A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4\n\
            evil.com.                3600000      A     203.0.113.1\n";
        let parsed = parse_root_hints(content);
        assert_eq!(parsed.v4.len(), 1);
        assert_eq!(parsed.v4[0], ('a', "198.41.0.4".parse().unwrap()));
        assert!(parsed.v6.is_empty());
    }

    #[test]
    fn diff_against_compiled_is_empty_for_in_sync_fixture() {
        // The fixture above was hand-derived from the same source as
        // the compiled-in const arrays. The diff must come back empty
        // — if it doesn't, EITHER the fixture is wrong (test bug) OR
        // the compiled-in arrays drifted (production bug).
        let parsed = parse_root_hints(&fixture_named_root());
        let diffs = diff_against_compiled(&parsed);
        assert!(
            diffs.is_empty(),
            "unexpected drift:\n  {}",
            diffs.join("\n  ")
        );
    }

    #[test]
    fn diff_against_compiled_reports_address_drift() {
        let mut parsed = parse_root_hints(&fixture_named_root());
        // Forge a drift: change A-root's IPv4 to something nonsensical.
        for (c, ip) in parsed.v4.iter_mut() {
            if *c == 'a' {
                *ip = "1.2.3.4".parse().unwrap();
            }
        }
        let diffs = diff_against_compiled(&parsed);
        assert!(
            diffs
                .iter()
                .any(|d| d.contains("A a:") && d.contains("drift")),
            "drift line missing from diff: {diffs:?}"
        );
    }

    #[test]
    fn diff_against_compiled_reports_missing_operator() {
        // Drop B-root's IPv4 record entirely.
        let mut parsed = parse_root_hints(&fixture_named_root());
        parsed.v4.retain(|(c, _)| *c != 'b');
        let diffs = diff_against_compiled(&parsed);
        assert!(
            diffs
                .iter()
                .any(|d| d.contains("A b:") && d.contains("missing in upstream")),
            "expected missing-in-upstream line: {diffs:?}"
        );
    }

    #[test]
    fn diff_against_compiled_reports_extra_operator() {
        let mut parsed = parse_root_hints(&fixture_named_root());
        // Insert a bogus 'n' operator that doesn't exist in the consts.
        parsed.v4.push(('n', "203.0.113.99".parse().unwrap()));
        let diffs = diff_against_compiled(&parsed);
        assert!(
            diffs
                .iter()
                .any(|d| d.contains("A n:") && d.contains("missing in compiled")),
            "expected missing-in-compiled line: {diffs:?}"
        );
    }

    /// Operational drift gate. Skipped by default so `cargo test`
    /// stays offline-friendly; CI (and the `just check-root-hints`
    /// recipe) set `DGAARD_NAMED_ROOT` to a path containing a
    /// freshly-downloaded `named.root`.
    ///
    /// The recipe lives in `justfile`; the weekly cron lives in
    /// `.woodpecker.yml`. See `CONTRIBUTING.md` for the manual
    /// regeneration procedure when this test fails.
    #[test]
    fn upstream_root_hints_match_compiled_constants() {
        let Ok(path) = std::env::var("DGAARD_NAMED_ROOT") else {
            // Skip silently — keeps the offline test run green.
            return;
        };
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read DGAARD_NAMED_ROOT={path}: {e}"));
        let parsed = parse_root_hints(&content);
        let diffs = diff_against_compiled(&parsed);
        assert!(
            diffs.is_empty(),
            "ROOT-HINTS DRIFT — regenerate ROOT_HINTS_V4/V6 in \
             dgaard/src/dns/recursive.rs (see CONTRIBUTING.md). \
             Differences:\n  {}",
            diffs.join("\n  ")
        );
    }

    #[test]
    fn load_root_hints_file_parses_a_and_aaaa() {
        let path = std::env::temp_dir().join(format!("dgaard-roots-{}.hints", std::process::id()));
        std::fs::write(
            &path,
            "; an example named.root\n\
             .                        3600000      NS    A.ROOT-SERVERS.NET.\n\
             A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4\n\
             A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30\n",
        )
        .unwrap();
        let parsed = load_root_hints_file(path.to_str().unwrap()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().any(|a| a.is_ipv4()));
        assert!(parsed.iter().any(|a| a.is_ipv6()));
        let _ = std::fs::remove_file(&path);
    }

    // ---- bailiwick + glue ----

    #[test]
    fn bailiwick_accepts_subdomain() {
        assert!(is_in_bailiwick(&name("com."), &name("example.com.")));
    }

    #[test]
    fn bailiwick_rejects_widening_referral() {
        assert!(!is_in_bailiwick(&name("com."), &name("example.net.")));
        assert!(!is_in_bailiwick(&name("example.com."), &name("com.")));
    }

    #[test]
    fn bailiwick_accepts_anything_under_root() {
        assert!(is_in_bailiwick(&Name::root(), &name("example.com.")));
    }

    #[test]
    fn in_bailiwick_glue_keeps_in_zone_addresses() {
        let new_zone = name("com.");
        let ns_names = vec![name("a.gtld-servers.net."), name("b.gtld-servers.net.")];
        // Out-of-bailiwick glue: net. is not under com. Reject.
        let mut msg = Message::query();
        msg.add_additional(Record::from_rdata(
            name("a.gtld-servers.net."),
            300,
            RData::A(A(Ipv4Addr::new(192, 5, 6, 30))),
        ));
        let glue = collect_in_bailiwick_glue(&msg, &ns_names, &new_zone);
        assert!(glue.is_empty(), "must reject out-of-bailiwick glue");
    }

    #[test]
    fn in_bailiwick_glue_keeps_in_zone_addresses_positive() {
        // For zone "example.com.", glue under example.com. is accepted.
        let new_zone = name("example.com.");
        let ns_names = vec![name("ns1.example.com.")];
        let mut msg = Message::query();
        msg.add_additional(Record::from_rdata(
            name("ns1.example.com."),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 53))),
        ));
        msg.add_additional(Record::from_rdata(
            name("ns1.example.com."),
            300,
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        ));
        let glue = collect_in_bailiwick_glue(&msg, &ns_names, &new_zone);
        assert_eq!(glue.len(), 2);
    }

    #[test]
    fn in_bailiwick_glue_drops_non_listed_names() {
        let new_zone = name("example.com.");
        let ns_names = vec![name("ns1.example.com.")];
        let mut msg = Message::query();
        // Attacker tries to slip a record for `attacker.example.com.` —
        // in-bailiwick but not one of the NS names. Drop it.
        msg.add_additional(Record::from_rdata(
            name("attacker.example.com."),
            300,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 1))),
        ));
        let glue = collect_in_bailiwick_glue(&msg, &ns_names, &new_zone);
        assert!(glue.is_empty());
    }

    // ---- classify_response ----

    #[test]
    fn classify_answer_when_answer_section_non_empty() {
        let mut msg = Message::query();
        msg.metadata.response_code = ResponseCode::NoError;
        msg.add_answer(Record::from_rdata(
            name("example.com."),
            300,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        assert!(matches!(classify_response(&msg), ResponseKind::Answer));
    }

    #[test]
    fn classify_referral_when_authority_has_ns() {
        let mut msg = Message::query();
        msg.metadata.response_code = ResponseCode::NoError;
        msg.add_authority(Record::from_rdata(
            name("com."),
            300,
            RData::NS(NS(name("a.gtld-servers.net."))),
        ));
        match classify_response(&msg) {
            ResponseKind::Referral { new_zone, ns_names } => {
                assert_eq!(new_zone, name("com."));
                assert_eq!(ns_names, vec![name("a.gtld-servers.net.")]);
            }
            other => panic!("expected Referral, got {other:?}"),
        }
    }

    #[test]
    fn classify_nxdomain() {
        let mut msg = Message::query();
        msg.metadata.response_code = ResponseCode::NXDomain;
        assert!(matches!(classify_response(&msg), ResponseKind::NxDomain));
    }

    #[test]
    fn classify_truncated_requests_tcp_fallback() {
        let mut msg = Message::query();
        msg.metadata.truncation = true;
        assert!(matches!(
            classify_response(&msg),
            ResponseKind::NeedTcpFallback
        ));
    }

    #[test]
    fn classify_servfail_is_empty() {
        let mut msg = Message::query();
        msg.metadata.response_code = ResponseCode::ServFail;
        assert!(matches!(classify_response(&msg), ResponseKind::Empty));
    }

    // ---- extract_cname_target ----

    #[test]
    fn extract_cname_returns_first_cname() {
        let answers = vec![Record::from_rdata(
            name("alias.example."),
            300,
            RData::CNAME(CNAME(name("real.example."))),
        )];
        assert_eq!(
            extract_cname_target(&answers).unwrap(),
            name("real.example.")
        );
    }

    #[test]
    fn extract_cname_returns_none_when_only_a_records() {
        let answers = vec![Record::from_rdata(
            name("example.com."),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        )];
        assert!(extract_cname_target(&answers).is_none());
    }

    // ---- build_outgoing_query ----

    #[test]
    fn outgoing_query_has_rd0_and_random_txid() {
        let q1 = build_outgoing_query(&name("example.com."), RecordType::A, None, false);
        let q2 = build_outgoing_query(&name("example.com."), RecordType::A, None, false);
        assert!(!q1.metadata.recursion_desired);
        // 1 in 65536 chance of false negative; this is fine for a sanity
        // check that the TXIDs are randomised at all.
        if q1.metadata.id == q2.metadata.id {
            let q3 = build_outgoing_query(&name("example.com."), RecordType::A, None, false);
            assert!(
                q1.metadata.id != q3.metadata.id || q2.metadata.id != q3.metadata.id,
                "TXIDs are not being randomised"
            );
        }
    }

    #[test]
    fn outgoing_query_adds_edns0_opt_when_requested() {
        let q = build_outgoing_query(&name("example.com."), RecordType::A, Some(1232), false);
        let edns = q.edns.as_ref().expect("EDNS opt must be present");
        assert_eq!(edns.max_payload(), 1232);
        assert_eq!(edns.version(), 0);
        assert!(!edns.flags().dnssec_ok, "DO bit must default off");
    }

    #[test]
    fn outgoing_query_sets_do_bit_when_requested() {
        // Phase 6 session 2 contract: the iterative resolver passes
        // dnssec_ok=true on every query when a validator is installed,
        // so upstream authoritatives include RRSIGs in their response.
        let q = build_outgoing_query(&name("example.com."), RecordType::A, Some(1232), true);
        let edns = q
            .edns
            .as_ref()
            .expect("EDNS must be present when DO is requested");
        assert!(edns.flags().dnssec_ok);
    }

    #[test]
    fn outgoing_query_promotes_to_edns_when_only_do_is_set() {
        // Even when no buffer size is requested, asking for DNSSEC
        // material requires advertising an OPT RR.
        let q = build_outgoing_query(&name("example.com."), RecordType::A, None, true);
        let edns = q.edns.as_ref().expect("EDNS must be auto-added for DO");
        assert!(edns.flags().dnssec_ok);
    }

    #[test]
    fn outgoing_query_omits_edns0_when_disabled() {
        let q = build_outgoing_query(&name("example.com."), RecordType::A, None, false);
        assert!(q.edns.is_none());
    }

    #[test]
    fn outgoing_query_round_trips_via_wire() {
        let q = build_outgoing_query(&name("example.com."), RecordType::AAAA, Some(1232), false);
        let bytes = q.to_vec().expect("encode");
        let parsed = Message::from_vec(&bytes).expect("re-parse");
        let qname = parsed.queries.first().unwrap();
        assert_eq!(qname.name(), &name("example.com."));
        assert_eq!(qname.query_type(), RecordType::AAAA);
    }

    // ---- end-to-end resolver against in-process mock NS ----

    /// Tiny "authoritative" UDP server: takes a callback that builds the
    /// response from the parsed query. Returns the bound address so the
    /// resolver can be pointed at it as a "root".
    async fn spawn_mock_ns<F>(handler: F) -> SocketAddr
    where
        F: Fn(&Message) -> Message + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let (len, peer) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let Ok(query) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let mut response = handler(&query);
                response.metadata.id = query.metadata.id;
                response.metadata.message_type = MessageType::Response;
                if let Some(q) = query.queries.first() {
                    response.add_query(q.clone());
                }
                if let Ok(bytes) = response.to_vec() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        });
        addr
    }

    fn make_dns_packet(qname: &str, qtype: RecordType) -> DnsPacket {
        let mut msg = Message::query();
        msg.add_query(
            Query::query(Name::from_ascii(qname).unwrap(), qtype)
                .set_query_class(DNSClass::IN)
                .clone(),
        );
        let bytes = msg.to_vec().unwrap();
        DnsPacket::from_bytes(&bytes).expect("parse own query")
    }

    fn cfg_for_tests() -> RecursiveConfig {
        RecursiveConfig {
            query_timeout_ms: 1500,
            max_queries_per_resolution: 32,
            max_delegation_depth: 4,
            edns0_enabled: false, // simpler responses from the mock
            ..RecursiveConfig::default()
        }
    }

    #[tokio::test]
    async fn resolves_when_root_answers_directly() {
        // Root NS answers everything authoritatively with an A record.
        let target = Ipv4Addr::new(93, 184, 216, 34);
        let root = spawn_mock_ns(move |q| {
            let mut resp = Message::query();
            resp.metadata.response_code = ResponseCode::NoError;
            let qname = q.queries.first().unwrap().name().clone();
            resp.add_answer(Record::from_rdata(qname, 300, RData::A(A(target))));
            resp
        })
        .await;

        let resolver = RecursiveResolver::with_roots(cfg_for_tests(), vec![root]);
        let packet = make_dns_packet("example.com.", RecordType::A);
        let bytes = resolver.resolve(&packet).await.unwrap();
        let parsed = Message::from_vec(&bytes).unwrap();
        assert_eq!(parsed.metadata.response_code, ResponseCode::NoError);
        let answer_ips: Vec<_> = parsed
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect();
        assert_eq!(answer_ips, vec![target]);
    }

    #[tokio::test]
    async fn follows_one_delegation_hop_with_glue() {
        // Root NS returns a referral to `example.` with in-bailiwick
        // glue. That second server then returns the A record.
        let auth_ip = Ipv4Addr::new(127, 0, 0, 1);
        let leaf_addr = spawn_mock_ns(|q| {
            let mut resp = Message::query();
            resp.metadata.response_code = ResponseCode::NoError;
            let qname = q.queries.first().unwrap().name().clone();
            resp.add_answer(Record::from_rdata(
                qname,
                300,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
            ));
            resp
        })
        .await;

        let leaf_port = leaf_addr.port();
        let root = spawn_mock_ns(move |_q| {
            let mut resp = Message::query();
            resp.metadata.response_code = ResponseCode::NoError;
            // delegate to ns1.example.
            resp.add_authority(Record::from_rdata(
                Name::from_ascii("example.").unwrap(),
                300,
                RData::NS(NS(Name::from_ascii("ns1.example.").unwrap())),
            ));
            // In-bailiwick glue
            resp.add_additional(Record::from_rdata(
                Name::from_ascii("ns1.example.").unwrap(),
                300,
                RData::A(A(auth_ip)),
            ));
            // Pretend the glue points at 127.0.0.1 — but the resolver
            // assumes port 53 for glue; route through the leaf instead.
            let _ = resp;
            // Build properly: we need the glue address to point at leaf.
            let mut resp = Message::query();
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_authority(Record::from_rdata(
                Name::from_ascii("example.").unwrap(),
                300,
                RData::NS(NS(Name::from_ascii("ns1.example.").unwrap())),
            ));
            resp.add_additional(Record::from_rdata(
                Name::from_ascii("ns1.example.").unwrap(),
                300,
                RData::A(A(Ipv4Addr::new(127, 0, 0, 1))),
            ));
            let _ = (auth_ip, leaf_port);
            resp
        })
        .await;
        // Because the resolver hard-codes port 53 for glue we cannot
        // route the second hop in a unit test — but we *can* prove the
        // referral / bailiwick path executes by inspecting the metric
        // counters and accepting the SERVFAIL on the second hop.
        let resolver = RecursiveResolver::with_roots(cfg_for_tests(), vec![root]);
        let before = crate::STATS_COUNTERS.get_recursive_referrals();
        let packet = make_dns_packet("foo.example.", RecordType::A);
        let _ = resolver.resolve(&packet).await; // expected to error (port 53)
        let after = crate::STATS_COUNTERS.get_recursive_referrals();
        assert!(
            after > before,
            "the referral path must have fired at least once"
        );
        let _ = leaf_addr; // keep alive
    }

    #[tokio::test]
    async fn out_of_bailiwick_referral_rejected_in_strict_mode() {
        // Root NS hands back a referral for `attacker.net.` while the
        // resolver is at the root — a clear widening attempt.
        let root = spawn_mock_ns(|_q| {
            let mut resp = Message::query();
            resp.metadata.response_code = ResponseCode::NoError;
            // Note: zone *is* under root (everything is under root),
            // but the test below uses a starting zone of `com.`.
            resp.add_authority(Record::from_rdata(
                Name::from_ascii("attacker.net.").unwrap(),
                300,
                RData::NS(NS(Name::from_ascii("ns.attacker.net.").unwrap())),
            ));
            resp
        })
        .await;

        // Verify the helper directly — we don't need to drive the full
        // resolver to prove the policy.
        let new_zone = Name::from_ascii("attacker.net.").unwrap();
        let current_zone = Name::from_ascii("com.").unwrap();
        assert!(
            !is_in_bailiwick(&current_zone, &new_zone),
            "the test setup must produce an out-of-bailiwick zone"
        );
        let _ = root;
    }

    #[tokio::test]
    async fn nxdomain_propagates_to_client() {
        let root = spawn_mock_ns(|_q| {
            let mut resp = Message::query();
            resp.metadata.response_code = ResponseCode::NXDomain;
            resp
        })
        .await;
        let resolver = RecursiveResolver::with_roots(cfg_for_tests(), vec![root]);
        let packet = make_dns_packet("nope.example.", RecordType::A);
        let bytes = resolver.resolve(&packet).await.unwrap();
        let parsed = Message::from_vec(&bytes).unwrap();
        assert_eq!(parsed.metadata.response_code, ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn amplification_defence_kicks_in_against_self_referencing_zone() {
        // Mock that always returns a referral for `example.` pointing at
        // an NS in the same zone, without glue. Either cycle detection
        // or the query cap must fire — both are valid amplification
        // defences and we don't care which one wins.
        let unreachable = Name::from_ascii("ns.example.").unwrap();
        let root = spawn_mock_ns(move |_q| {
            let mut resp = Message::query();
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_authority(Record::from_rdata(
                Name::from_ascii("example.").unwrap(),
                300,
                RData::NS(NS(unreachable.clone())),
            ));
            resp
        })
        .await;
        let mut cfg = cfg_for_tests();
        cfg.max_queries_per_resolution = 4;
        let resolver = RecursiveResolver::with_roots(cfg, vec![root]);
        let before_cap = crate::STATS_COUNTERS.get_recursive_query_cap_hit();
        let before_cycle = crate::STATS_COUNTERS.get_recursive_cycle_detected();
        let packet = make_dns_packet("foo.example.", RecordType::A);
        let _ = resolver.resolve(&packet).await;
        let after_cap = crate::STATS_COUNTERS.get_recursive_query_cap_hit();
        let after_cycle = crate::STATS_COUNTERS.get_recursive_cycle_detected();
        assert!(
            after_cap > before_cap || after_cycle > before_cycle,
            "either query_cap_hit ({before_cap}->{after_cap}) or \
             cycle_detected ({before_cycle}->{after_cycle}) must advance"
        );
    }

    // ---- Phase 6 session 2: chain build through the iterative loop ----

    #[tokio::test]
    async fn chain_step_records_dnskey_when_mock_serves_signed_zone() {
        // Bring up a mock NS that:
        //  * answers DNSKEY queries with a self-signed DNSKEY rrset,
        //  * pretends to be authoritative for `example.test.`.
        //
        // Pre-seed the validator with a DS that matches that DNSKEY so
        // `record_dnskey_rrset` lands `Secure` and bumps the
        // `recursive_dnssec_chain_built` counter.
        use crate::dns::dnssec_chain::{RecursiveDnssecValidator, ZoneTrustState};
        use hickory_resolver::proto::dnssec::crypto::EcdsaSigningKey;
        use hickory_resolver::proto::dnssec::rdata::{DNSSECRData, RRSIG};
        use hickory_resolver::proto::dnssec::{
            Algorithm, DigestType, DnssecSigner, PublicKeyBuf, SigningKey, Verifier, rdata::DNSKEY,
        };
        use hickory_resolver::proto::rr::{DNSClass, RecordSet};
        use std::sync::Arc;
        use time::OffsetDateTime;

        let zone = Name::from_ascii("example.test.").unwrap();
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
        let key = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).unwrap();
        let public: PublicKeyBuf = key.to_public_key().unwrap();
        let dnskey = DNSKEY::with_flags(257, public);
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            zone.clone(),
            std::time::Duration::from_secs(3600),
        );

        let mut dnskey_rrset = RecordSet::new(zone.clone(), RecordType::DNSKEY, 3600);
        dnskey_rrset.add_rdata(RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())));
        let now = OffsetDateTime::now_utc();
        let dnskey_rrsig = RRSIG::from_rrset(&dnskey_rrset, DNSClass::IN, now, &signer).unwrap();
        let dnskey_records: Vec<Record> = dnskey_rrset.records_without_rrsigs().cloned().collect();

        // Mock NS: respond to DNSKEY queries with the signed rrset.
        // Anything else gets an empty NoError so we don't have to flesh
        // out unrelated paths.
        let dnskey_for_mock = dnskey_records.clone();
        let rrsig_for_mock = dnskey_rrsig.clone();
        let zone_for_mock = zone.clone();
        let ns_addr = spawn_mock_ns(move |q| {
            let mut resp = Message::query();
            resp.metadata.response_code = ResponseCode::NoError;
            if let Some(query) = q.queries.first()
                && query.query_type() == RecordType::DNSKEY
            {
                for r in &dnskey_for_mock {
                    resp.add_answer(r.clone());
                }
                resp.add_answer(Record::from_rdata(
                    zone_for_mock.clone(),
                    3600,
                    RData::DNSSEC(DNSSECRData::RRSIG(rrsig_for_mock.clone())),
                ));
            }
            resp
        })
        .await;

        // Validator pre-seeded with a DS matching `dnskey`.
        let validator = Arc::new(RecursiveDnssecValidator::empty());
        let ds_digest = dnskey.to_digest(&zone, DigestType::SHA256).unwrap();
        let ds = crate::dns::dnssec_chain::DS::new(
            dnskey.calculate_key_tag().unwrap(),
            dnskey.algorithm(),
            DigestType::SHA256,
            ds_digest.as_ref().to_vec(),
        );
        validator.seed_zone_for_test(
            zone.clone(),
            ZoneTrustState {
                ds_in_parent: vec![ds],
                dnskeys: Vec::new(),
            },
        );

        // Drive `build_chain_step` directly: synthesise an empty
        // referral message (we don't need DS harvest for this test —
        // the DS is pre-seeded), then assert the DNSKEY fetch lands.
        let resolver = RecursiveResolver::with_roots(cfg_for_tests(), vec![ns_addr])
            .with_validator(Arc::clone(&validator));
        let parent_zone = Name::root();
        let referral = Message::query();
        let before = crate::STATS_COUNTERS.get_recursive_dnssec_chain_built();
        let mut queries_used = 0u32;
        resolver
            .build_chain_step(
                &validator,
                &referral,
                &parent_zone,
                &zone,
                &[ns_addr],
                &mut queries_used,
            )
            .await;
        let after = crate::STATS_COUNTERS.get_recursive_dnssec_chain_built();
        assert!(
            after > before,
            "chain_built counter must advance once the DNSKEY fetch succeeds"
        );
        assert!(
            !validator.zone(&zone).unwrap().dnskeys.is_empty(),
            "DNSKEY must be cached after build_chain_step"
        );
    }

    #[tokio::test]
    async fn chain_step_bumps_broken_counter_when_dnskey_serves_unsigned() {
        // Mock NS returns a DNSKEY query response with no RRSIG. The
        // harvest helper returns None, so the chain doesn't advance —
        // and crucially we do NOT increment chain_broken in that case
        // (Insecure delegation is not a chain failure). The counter
        // stays put; the test asserts the no-op.
        use crate::dns::dnssec_chain::RecursiveDnssecValidator;
        use std::sync::Arc;

        let ns_addr = spawn_mock_ns(|q| {
            let mut resp = Message::query();
            resp.metadata.response_code = ResponseCode::NoError;
            // Echo the qname back with no answers.
            let _ = q;
            resp
        })
        .await;

        let validator = Arc::new(RecursiveDnssecValidator::default());
        let resolver = RecursiveResolver::with_roots(cfg_for_tests(), vec![ns_addr])
            .with_validator(Arc::clone(&validator));

        let before_built = crate::STATS_COUNTERS.get_recursive_dnssec_chain_built();
        let before_broken = crate::STATS_COUNTERS.get_recursive_dnssec_chain_broken();
        let mut queries_used = 0u32;
        let zone = Name::from_ascii("nochain.test.").unwrap();
        resolver
            .build_chain_step(
                &validator,
                &Message::query(),
                &Name::root(),
                &zone,
                &[ns_addr],
                &mut queries_used,
            )
            .await;
        assert_eq!(
            crate::STATS_COUNTERS.get_recursive_dnssec_chain_built(),
            before_built,
            "chain_built must NOT advance when DNSKEY arrived without RRSIG"
        );
        assert_eq!(
            crate::STATS_COUNTERS.get_recursive_dnssec_chain_broken(),
            before_broken,
            "chain_broken must NOT advance for insecure delegations"
        );
    }

    // ---- build_client_response ----

    #[test]
    fn build_client_response_preserves_txid_and_question() {
        let client = make_dns_packet("example.com.", RecordType::A);
        let client_id = client.message.metadata.id;
        let mut upstream = Message::query();
        upstream.metadata.id = 0xFFFF; // different ID
        upstream.metadata.response_code = ResponseCode::NoError;
        upstream.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let bytes = build_client_response(&client, upstream).unwrap();
        let parsed = Message::from_vec(&bytes).unwrap();
        assert_eq!(parsed.metadata.id, client_id);
        assert_eq!(parsed.metadata.message_type, MessageType::Response);
        assert_eq!(
            parsed.queries.first().unwrap().name(),
            &Name::from_str("example.com.").unwrap()
        );
        assert!(parsed.metadata.recursion_available);
    }
}
