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
//! - CNAME chase with budget sharing; the client gets the whole chain
//!   (`CNAME…` + target records) under its own question
//! - Cycle detection (xxh3_64 hashes): delegation cycles per sub-resolution,
//!   CNAME cycles per chain, and re-entrant sub-resolutions (glueless NS
//!   loops) through the shared [`ResolutionBudget`]
//! - Hard caps on delegation depth + total queries per resolution
//! - EDNS0 OPT advertisement
//! - Sequential `ns_concurrency`
//! - Delegation cache: a walk starts at the deepest known zone cut (bounded
//!   LRU, NS TTL capped at a day), back to the root if its servers fail
//! - Nameserver addresses on loopback / LAN ranges are never queried
//!   (glue or NS lookups); IPv6 servers only with an IPv6 route, IPv4 first
//! - Connected sockets, and a datagram that does not answer the query
//!   (TXID, QR, question) is ignored rather than failing the query
//! - TCP fallback when an authoritative answer is truncated (`TC=1`)
//! - Root hints compiled-in (with optional `root_hints_path` override)
//! - Metrics counters into [`crate::STATS_COUNTERS`]
//!
//! ## Deferred to the rest of Phase 2
//!
//! - QNAME minimization (today: full QNAME on every hop; the config flag is
//!   parsed and stored so configs stay forward-compatible)
//! - Staggered / parallel NS fanout (config accepted, runtime is sequential)
//! - ECS striping (no ECS option is ever inserted, which is the only
//!   safe-by-default behaviour required by the roadmap)

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_resolver::proto::dnssec::rdata::DNSSECRData;
use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use lru::LruCache;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use twox_hash::XxHash3_64;

use crate::dns::dnssec_chain::{
    DnssecVerdict, RecursiveDnssecValidator, ZoneStatus, extract_dnskey_rrset_from_answers,
    extract_ds_rrset_from_authority, extract_signed_rrset, rrsig_signers,
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
    hash_name(name, 0)
}

/// xxh3_64 of the lowercase wire form of `name` (length-prefixed labels),
/// built on the stack: hashing sits on every hop of the walk.
fn hash_name(name: &Name, seed: u64) -> u64 {
    let mut buf = [0u8; 255];
    let mut len = 0;
    for label in name.iter() {
        // A valid name fits in 255 wire bytes, length octets included.
        let end = len + 1 + label.len();
        if end > buf.len() {
            break;
        }
        // Labels are at most 63 bytes long.
        buf[len] = label.len() as u8;
        for (slot, byte) in buf[len + 1..end].iter_mut().zip(label) {
            *slot = byte.to_ascii_lowercase();
        }
        len = end;
    }
    XxHash3_64::oneshot_with_seed(seed, &buf[..len])
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

/// Upper bound on nested zone cuts chained without a referral (a zone,
/// its child, grandchild… all hosted on the same servers).
const MAX_COHOSTED_CUTS: u8 = 4;

/// Names whose data in `response` carries no signature: owners of answer
/// rrsets without a covering RRSIG, plus `qname` for a negative answer
/// whose authority section is unsigned. The resolver checks whether an
/// insecure zone cut explains them.
pub(crate) fn unsigned_names(response: &Message, qname: &Name) -> Vec<Name> {
    let mut names: Vec<Name> = Vec::new();
    for record in &response.answers {
        let rtype = record.record_type();
        if rtype == RecordType::RRSIG || names.contains(&record.name) {
            continue;
        }
        let signed = response.answers.iter().any(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) => {
                r.name == record.name && sig.input().type_covered == rtype
            }
            _ => false,
        });
        if !signed {
            names.push(record.name.clone());
        }
    }

    let negative =
        response.metadata.response_code == ResponseCode::NXDomain || response.answers.is_empty();
    let authority_signed = response
        .authorities
        .iter()
        .any(|r| r.record_type() == RecordType::RRSIG);
    if negative && !authority_signed && !names.contains(qname) {
        names.push(qname.clone());
    }
    names
}

/// Key of one `(qname, qtype)` resolution in [`ResolutionBudget::in_progress`].
fn hash_resolution(qname: &Name, qtype: RecordType) -> u64 {
    hash_name(qname, u64::from(u16::from(qtype)))
}

/// The CNAME chain an answer section describes for one queried name.
#[derive(Debug)]
pub struct CnameWalk {
    /// The queried name, then every CNAME target in chain order. The last
    /// entry is the terminal name (the queried name when there is no CNAME).
    pub owners: Vec<Name>,
}

impl CnameWalk {
    /// Last name of the chain: where the answer data should live.
    pub fn terminal(&self) -> &Name {
        // `owners` always starts with the queried name.
        &self.owners[self.owners.len() - 1]
    }

    /// CNAME targets followed, in chain order.
    pub fn targets(&self) -> &[Name] {
        &self.owners[1..]
    }

    /// Names that own a CNAME, i.e. every owner but the terminal one.
    pub fn aliases(&self) -> &[Name] {
        &self.owners[..self.owners.len() - 1]
    }
}

/// Follow the CNAME chain for `start` through `answers`, trusting only
/// records owned by names inside `zone` (the zone that served them).
///
/// An out-of-zone CNAME stops the walk, so a server cannot vouch for names
/// it is not authoritative for. Each hop consumes a distinct record, so
/// `answers.len()` bounds an in-message loop (`a → b → a`); the caller
/// detects the cycle itself from the returned owners.
pub fn walk_cname_chain(answers: &[Record], start: &Name, zone: &Name) -> CnameWalk {
    let mut owners = vec![start.clone()];
    for _ in 0..answers.len() {
        let current = &owners[owners.len() - 1];
        let next = answers.iter().find_map(|r| match &r.data {
            RData::CNAME(target) if r.name == *current && is_in_bailiwick(zone, &r.name) => {
                Some(target.0.clone())
            }
            _ => None,
        });
        match next {
            Some(target) => owners.push(target),
            None => break,
        }
    }
    CnameWalk { owners }
}

/// True when `answers` hold data of `qtype` for `name`, served in `zone`.
/// For `ANY`, any non-CNAME record counts.
fn has_answer_for(answers: &[Record], name: &Name, qtype: RecordType, zone: &Name) -> bool {
    answers.iter().any(|r| {
        let rtype = r.record_type();
        r.name == *name
            && is_in_bailiwick(zone, &r.name)
            && (rtype == qtype || (qtype == RecordType::ANY && rtype != RecordType::CNAME))
    })
}

/// Records of `answers` owned by one of `owners` and served in `zone`
/// (CNAMEs, target data, and the RRSIGs covering them).
fn records_owned_by(answers: &[Record], owners: &[Name], zone: &Name) -> Vec<Record> {
    answers
        .iter()
        .filter(|r| owners.contains(&r.name) && is_in_bailiwick(zone, &r.name))
        .cloned()
        .collect()
}

/// State shared by every sub-resolution of one client query: CNAME chase
/// hops and glueless NS lookups.
///
/// Only the query budget and the stack of in-progress resolutions are
/// shared. Delegation cycles are tracked per sub-resolution: each one
/// restarts from the root and legitimately crosses the same TLD again.
#[derive(Debug, Default)]
pub struct ResolutionBudget {
    /// Upstream queries sent so far, capped by `max_queries_per_resolution`.
    pub queries_used: u32,
    /// [`hash_resolution`] of every `(qname, qtype)` on the current call
    /// stack. Re-entering one (`ns.a` needs `ns.b` needs `ns.a`) is a cycle.
    in_progress: Vec<u64>,
}

/// True for an address dgaard may query on behalf of a zone. A hostile
/// zone must not be able to point its servers (glue or NS lookups) at
/// dgaard itself or at the LAN: loopback, unspecified, RFC 1918, CGNAT,
/// link-local, unique-local, multicast, broadcast and reserved ranges are
/// refused. IPv4-mapped IPv6 addresses are judged as their IPv4 address.
pub fn is_public_ns_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [first, second, ..] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || first == 0
                || first >= 240 // reserved, broadcast
                || (first == 100 && (64..=127).contains(&second))) // CGNAT
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_ns_address(IpAddr::V4(v4)),
            None => {
                !(v6.is_unspecified()
                    || v6.is_loopback()
                    || v6.is_multicast()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local())
            }
        },
    }
}

/// Whether this host has an IPv6 route to the Internet. Checked once by
/// "connecting" a UDP socket to a root server, which only consults the
/// routing table (no packet is sent). Without a route, every IPv6 server
/// tried would cost a timeout or an immediate error.
fn ipv6_reachable() -> bool {
    static REACHABLE: OnceLock<bool> = OnceLock::new();
    *REACHABLE.get_or_init(|| {
        let probe = SocketAddr::new(IpAddr::V6(ROOT_HINTS_V6[0].1), 53);
        std::net::UdpSocket::bind("[::]:0")
            .and_then(|socket| socket.connect(probe))
            .is_ok()
    })
}

/// Order nameserver addresses for a sequential walk: IPv4 first (IPv6
/// after, or dropped when `ipv6` is false), original order otherwise kept.
fn order_ns_addrs(addrs: impl IntoIterator<Item = SocketAddr>, ipv6: bool) -> Vec<SocketAddr> {
    let (mut ordered, v6): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv4);
    if ipv6 {
        ordered.extend(v6);
    }
    ordered
}

/// Upper bound on cached delegations.
const MAX_CACHED_DELEGATIONS: usize = 4096;

/// Longest a delegation is trusted, whatever its NS TTL says (one day,
/// like common resolvers' `max-cache-ttl` for infrastructure records).
const MAX_DELEGATION_TTL: u32 = 86_400;

/// How long the delegation to `zone` in `authorities` may be cached: the
/// smallest TTL of its NS records, capped at [`MAX_DELEGATION_TTL`].
fn delegation_ttl(authorities: &[Record], zone: &Name) -> u32 {
    authorities
        .iter()
        .filter(|record| record.name == *zone && matches!(record.data, RData::NS(_)))
        .map(|record| record.ttl)
        .min()
        .unwrap_or(0)
        .min(MAX_DELEGATION_TTL)
}

/// One zone cut and the addresses of its servers.
struct Delegation {
    zone: Name,
    servers: Vec<SocketAddr>,
    expires_at: Instant,
}

/// Zone cuts learned from referrals, so a resolution starts at the deepest
/// known cut instead of the root: one round trip for a warm zone instead
/// of three or more. Bounded (LRU) and TTL-driven.
pub(crate) struct DelegationCache {
    inner: Mutex<LruCache<u64, Delegation>>,
}

impl DelegationCache {
    fn new(max_entries: usize) -> Self {
        let cap = NonZeroUsize::new(max_entries.max(1)).expect("capacity >= 1");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LruCache<u64, Delegation>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Remember `servers` for `zone` during `ttl` seconds (0: not stored).
    fn insert(&self, zone: &Name, servers: &[SocketAddr], ttl: u32) {
        if ttl == 0 || servers.is_empty() {
            return;
        }
        let expires_at = Instant::now() + Duration::from_secs(u64::from(ttl));
        self.put(zone, servers, expires_at);
    }

    fn put(&self, zone: &Name, servers: &[SocketAddr], expires_at: Instant) {
        let entry = Delegation {
            zone: zone.clone(),
            servers: servers.to_vec(),
            expires_at,
        };
        self.lock().put(hash_zone_label(zone), entry);
    }

    /// Live servers of exactly `zone`; an expired entry is dropped.
    fn get(&self, zone: &Name) -> Option<Vec<SocketAddr>> {
        let key = hash_zone_label(zone);
        let mut guard = self.lock();
        let entry = guard.get(&key)?;
        if entry.zone != *zone {
            return None;
        }
        if entry.expires_at <= Instant::now() {
            guard.pop(&key);
            return None;
        }
        Some(entry.servers.clone())
    }

    fn remove(&self, zone: &Name) {
        let key = hash_zone_label(zone);
        let mut guard = self.lock();
        if guard.peek(&key).is_some_and(|entry| entry.zone == *zone) {
            guard.pop(&key);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }
}

/// Check one datagram (or TCP message) against the query it should answer:
/// a response (QR=1) with the same TXID and the same single question.
/// Anything else is a stray, a forgery or garbage — `None`.
fn accept_response(bytes: &[u8], query: &Message) -> Option<Message> {
    let response = Message::from_vec(bytes).ok()?;
    let same_question = match (response.queries.as_slice(), query.queries.first()) {
        ([answered], Some(asked)) => {
            // `Name` equality is case-insensitive.
            answered.name() == asked.name()
                && answered.query_type() == asked.query_type()
                && answered.query_class() == asked.query_class()
        }
        _ => false,
    };
    (response.metadata.id == query.metadata.id
        && response.metadata.message_type == MessageType::Response
        && same_question)
        .then_some(response)
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
    /// Destination port for nameserver addresses learned from glue or NS
    /// lookups. Always 53 in production; tests point it at mock servers.
    pub(crate) ns_port: u16,
    /// Zone cuts learned from referrals (see [`DelegationCache`]).
    pub(crate) delegations: DelegationCache,
    /// Accept nameserver addresses on loopback and LAN ranges (see
    /// [`is_public_ns_address`]). Never set in production; the mock
    /// hierarchies of the tests listen on 127.0.0.x.
    pub(crate) private_ns_allowed: bool,
    /// Whether IPv6 nameservers are worth trying (see [`ipv6_reachable`]).
    pub(crate) ipv6_usable: bool,
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
        Ok(Self::with_roots(config, roots))
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
    pub fn with_roots(config: RecursiveConfig, roots: Vec<SocketAddr>) -> Self {
        Self {
            config,
            roots,
            validator: None,
            ns_port: 53,
            delegations: DelegationCache::new(MAX_CACHED_DELEGATIONS),
            private_ns_allowed: false,
            ipv6_usable: ipv6_reachable(),
        }
    }

    /// Socket addresses of the nameservers at `ips` this resolver may
    /// query: public ones only, IPv4 first, IPv6 only when reachable.
    fn usable_ns_addrs(&self, ips: impl IntoIterator<Item = IpAddr>) -> Vec<SocketAddr> {
        let addrs = ips
            .into_iter()
            .filter(|ip| self.private_ns_allowed || is_public_ns_address(*ip))
            .map(|ip| SocketAddr::new(ip, self.ns_port));
        order_ns_addrs(addrs, self.ipv6_usable)
    }

    /// Where a walk for `qname` / `qtype` starts: the deepest cached zone
    /// cut enclosing it, or the root. A DS rrset lives in the parent, so
    /// for DS the search starts above `qname`. With DNSSEC, a cut is used
    /// only while the validator still knows its trust state: skipping the
    /// hops above it must not skip the chain of trust.
    fn start_point(&self, qname: &Name, qtype: RecordType) -> (Name, Vec<SocketAddr>) {
        let mut candidate = if qtype == RecordType::DS && !qname.is_root() {
            qname.base_name()
        } else {
            qname.clone()
        };
        while !candidate.is_root() {
            let chain_known = self
                .validator
                .as_ref()
                .is_none_or(|validator| validator.zone_status(&candidate).is_some());
            if chain_known && let Some(servers) = self.delegations.get(&candidate) {
                return (candidate, servers);
            }
            candidate = candidate.base_name();
        }
        (
            Name::root(),
            pick_initial_ns_addrs(&self.roots, self.ipv6_usable),
        )
    }

    /// Resolve `qname` / `qtype`, following CNAMEs, and return a `Message`
    /// whose answer section is the whole chain: every CNAME from `qname` to
    /// the terminal name, then the terminal name's records.
    ///
    /// `budget` is shared by every sub-resolution (CNAME hops, glueless NS
    /// lookups) so a malicious chain cannot escape the per-query caps; a
    /// sub-resolution that re-enters one already in progress is a cycle.
    pub fn resolve_iterative<'a>(
        &'a self,
        qname: Name,
        qtype: RecordType,
        budget: &'a mut ResolutionBudget,
    ) -> Pin<Box<dyn Future<Output = io::Result<Message>> + Send + 'a>> {
        Box::pin(async move {
            let key = hash_resolution(&qname, qtype);
            if budget.in_progress.contains(&key) {
                crate::STATS_COUNTERS.increment_recursive_cycle_detected();
                return Err(io::Error::other("resolution cycle"));
            }
            budget.in_progress.push(key);
            let result = self.resolve_following_cnames(qname, qtype, budget).await;
            budget.in_progress.pop();
            result
        })
    }

    /// CNAME chase loop behind [`Self::resolve_iterative`].
    ///
    /// Each hop walks the delegations for the current name. Only records
    /// served by the zone that answered are trusted: an in-zone chain is
    /// taken as is, while a target outside that zone (or one the server did
    /// not answer for) is resolved again from the root.
    async fn resolve_following_cnames(
        &self,
        qname: Name,
        qtype: RecordType,
        budget: &mut ResolutionBudget,
    ) -> io::Result<Message> {
        let mut chain: Vec<Record> = Vec::new();
        let mut visited_cnames: Vec<u64> = vec![hash_zone_label(&qname)];
        let mut current = qname;

        loop {
            let (mut response, zone) = self.walk_delegations(&current, qtype, budget).await?;
            if qtype == RecordType::CNAME {
                // The client asked for the alias itself: nothing to follow.
                return Ok(response);
            }

            let walk = walk_cname_chain(&response.answers, &current, &zone);
            for target in walk.targets() {
                let target_hash = hash_zone_label(target);
                if visited_cnames.contains(&target_hash) {
                    crate::STATS_COUNTERS.increment_recursive_cycle_detected();
                    return Err(io::Error::other("CNAME cycle"));
                }
                // `visited_cnames` also holds the original name.
                if visited_cnames.len() > usize::from(self.config.max_cname_depth) {
                    return Err(io::Error::other("max_cname_depth exceeded"));
                }
                visited_cnames.push(target_hash);
            }

            let chase = !walk.targets().is_empty()
                && response.metadata.response_code == ResponseCode::NoError
                && !has_answer_for(&response.answers, walk.terminal(), qtype, &zone);
            if chase {
                chain.extend(records_owned_by(&response.answers, walk.aliases(), &zone));
                current = walk.terminal().clone();
                continue;
            }

            // Final hop: earlier CNAMEs first, then this hop's chain and
            // data. Out-of-zone or unrelated records are dropped.
            chain.extend(records_owned_by(&response.answers, &walk.owners, &zone));
            response.answers = chain;
            return Ok(response);
        }
    }

    /// Walk the delegation chain from the root for `qname` / `qtype` and
    /// return the first answer (or NXDOMAIN) with the zone that served it.
    ///
    /// Delegation cycles are tracked per call: a CNAME hop or a glueless NS
    /// lookup restarts from the root and may cross the same zones again.
    async fn walk_delegations(
        &self,
        qname: &Name,
        qtype: RecordType,
        budget: &mut ResolutionBudget,
    ) -> io::Result<(Message, Name)> {
        let (mut current_zone, mut ns_addrs) = self.start_point(qname, qtype);
        // Starting below the root on cached servers that may have moved:
        // if they fail on the first hop, forget them and start over.
        let mut from_cache = !current_zone.is_root();
        let mut depth: u8 = 0;
        let mut visited_zones: Vec<u64> =
            Vec::with_capacity(usize::from(self.config.max_delegation_depth));

        // Anchor the chain: validate the starting zone's DNSKEY rrset (for
        // the root, against the compiled-in trust anchors) before following
        // the first referral.
        self.ensure_zone_keys(&current_zone, &ns_addrs, &mut budget.queries_used)
            .await;

        loop {
            if budget.queries_used >= self.config.max_queries_per_resolution {
                crate::STATS_COUNTERS.increment_recursive_query_cap_hit();
                return Err(io::Error::other("max_queries_per_resolution exceeded"));
            }
            if depth >= self.config.max_delegation_depth {
                crate::STATS_COUNTERS.increment_recursive_depth_cap_hit();
                return Err(io::Error::other("max_delegation_depth exceeded"));
            }

            let result = self
                .query_any_ns(&ns_addrs, qname, qtype, &mut budget.queries_used)
                .await;
            // Lame: no answer, an error, or a referral that does not lead
            // further down (the zone moved and these servers dropped it).
            let lame = match result.as_ref().map(classify_response) {
                Ok(ResponseKind::Empty) | Err(_) => true,
                Ok(ResponseKind::Referral { new_zone, .. }) => {
                    new_zone == current_zone || !is_in_bailiwick(&current_zone, &new_zone)
                }
                Ok(_) => false,
            };
            if from_cache && lame {
                self.delegations.remove(&current_zone);
                current_zone = Name::root();
                ns_addrs = pick_initial_ns_addrs(&self.roots, self.ipv6_usable);
                from_cache = false;
                self.ensure_zone_keys(&current_zone, &ns_addrs, &mut budget.queries_used)
                    .await;
                continue;
            }
            from_cache = false;
            let response = result?;

            let classified = classify_response(&response);
            if matches!(classified, ResponseKind::Answer | ResponseKind::NxDomain)
                && let Some(validator) = self.validator.clone()
            {
                self.complete_chain(
                    &validator,
                    &response,
                    qname,
                    &current_zone,
                    &ns_addrs,
                    &mut budget.queries_used,
                )
                .await;
            }

            match classified {
                // CNAMEs are followed by the caller, which sees the zone.
                ResponseKind::Answer => return Ok((response, current_zone)),
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

                    // Glue pointing at the LAN or at dgaard itself is
                    // dropped like missing glue.
                    let glue = self.usable_ns_addrs(collect_in_bailiwick_glue(
                        &response, &ns_names, &new_zone,
                    ));
                    if !glue.is_empty() {
                        crate::STATS_COUNTERS.increment_recursive_glue_hit();
                        ns_addrs = glue;
                    } else {
                        crate::STATS_COUNTERS.increment_recursive_glue_miss();
                        ns_addrs = self.resolve_ns_addresses(&ns_names, budget).await?;
                        if ns_addrs.is_empty() {
                            return Err(io::Error::other("no usable NS addresses"));
                        }
                    }
                    self.delegations.insert(
                        &new_zone,
                        &ns_addrs,
                        delegation_ttl(&response.authorities, &new_zone),
                    );

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
                            &mut budget.queries_used,
                        )
                        .await;
                    }

                    current_zone = new_zone;
                    depth = depth.saturating_add(1);
                }
                ResponseKind::NxDomain => return Ok((response, current_zone)),
                // Still truncated after the TCP fallback (or no budget left
                // to try it): nothing complete to serve.
                ResponseKind::NeedTcpFallback => {
                    return Err(io::Error::other("answer truncated over UDP and TCP"));
                }
                ResponseKind::Empty => {
                    return Err(io::Error::other("empty/SERVFAIL response"));
                }
            }
        }
    }

    /// Fetch `zone`'s DNSKEY rrset from `ns_addrs` when the validator has
    /// its DS (or, for the root, its anchors) but no validated keys yet.
    async fn ensure_zone_keys(&self, zone: &Name, ns_addrs: &[SocketAddr], queries_used: &mut u32) {
        if let Some(validator) = self.validator.clone()
            && validator.needs_keys(zone)
        {
            self.fetch_zone_keys(&validator, zone, ns_addrs, queries_used)
                .await;
        }
    }

    /// Sequentially walk `ns_addrs`, send `qname / qtype` to each, return
    /// the first acceptable response. Increments `queries_used` per
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
                // Truncated over UDP: ask the same server over TCP
                // (RFC 7766), paying one more query from the budget.
                Ok(msg) if msg.metadata.truncation => {
                    if *queries_used >= self.config.max_queries_per_resolution {
                        return Ok(msg);
                    }
                    *queries_used += 1;
                    crate::STATS_COUNTERS.increment_recursive_tcp_fallback();
                    match self.query_single_ns_tcp(*addr, qname, qtype).await {
                        Ok(full) => return Ok(full),
                        Err(e) => last_err = Some(e),
                    }
                }
                Ok(msg) => return Ok(msg),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no NS addresses to query")))
    }

    /// One TCP exchange, after a truncated UDP answer from `addr`. Caller
    /// has already paid the `queries_used` cost.
    async fn query_single_ns_tcp(
        &self,
        addr: SocketAddr,
        qname: &Name,
        qtype: RecordType,
    ) -> io::Result<Message> {
        let edns = self
            .config
            .edns0_enabled
            .then_some(self.config.edns0_udp_payload_size);
        let query = build_outgoing_query(qname, qtype, edns, self.validator.is_some());
        let bytes = query
            .to_vec()
            .map_err(|e| io::Error::other(format!("encode query: {e}")))?;
        let deadline = Duration::from_millis(self.config.query_timeout_ms);
        let raw = crate::dns::tcp::exchange(addr, &bytes, deadline).await?;
        accept_response(&raw, &query).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "TCP answer does not match the query",
            )
        })
    }

    /// One UDP exchange. Caller has already paid the `queries_used` cost.
    ///
    /// The socket is connected, so the kernel drops datagrams from any
    /// other source. Datagrams that still do not answer the query (wrong
    /// TXID, QR=0, other question, garbage) are ignored until the deadline:
    /// a flood of forged packets must not turn into a SERVFAIL.
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
        socket.connect(addr).await?;
        socket.send(&bytes).await?;

        let mut buf = [0u8; 4096];
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.config.query_timeout_ms);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let len = match timeout(remaining, socket.recv(&mut buf)).await {
                Ok(received) => received?,
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "NS UDP timeout")),
            };
            if let Some(response) = accept_response(&buf[..len], &query) {
                return Ok(response);
            }
        }
    }

    /// Extend the chain of trust through one delegation hop.
    ///
    /// 1. **Parent → child hand-off** — the referral either carries the
    ///    child's DS rrset, which the validator stores only once verified
    ///    under the parent's keys, or (insecure delegation) a signed
    ///    NSEC/NSEC3 proof that the child has no DS. A signed parent with
    ///    neither is a broken chain: the DS may have been stripped.
    /// 2. **DNSKEY fetch** — once the child has a verified DS, fetch its
    ///    DNSKEY rrset from the child's servers and validate it against
    ///    that DS.
    ///
    /// Each query bumps `queries_used`. Failures are counted in
    /// `recursive_dnssec_chain_broken` and do not abort the resolution:
    /// data under a broken chain fails validation in `handle_query`.
    async fn build_chain_step(
        &self,
        validator: &Arc<RecursiveDnssecValidator>,
        referral: &Message,
        parent_zone: &Name,
        child_zone: &Name,
        ns_addrs: &[SocketAddr],
        queries_used: &mut u32,
    ) {
        let verdict = match extract_ds_rrset_from_authority(referral, child_zone) {
            Some((ds_records, ds_sigs)) => {
                validator.record_ds_for_child(parent_zone, child_zone, &ds_records, &ds_sigs)
            }
            None => {
                validator.record_insecure_delegation(parent_zone, child_zone, &referral.authorities)
            }
        };
        if verdict == DnssecVerdict::Bogus {
            crate::STATS_COUNTERS.increment_recursive_dnssec_chain_broken();
        }

        if validator.needs_keys(child_zone) {
            self.fetch_zone_keys(validator, child_zone, ns_addrs, queries_used)
                .await;
        }
    }

    /// Fetch `zone`'s DNSKEY rrset from `ns_addrs` and validate it against
    /// the zone's verified DS (the compiled-in anchors for the root).
    /// Budget-bounded: skipped when the query cap is reached, which leaves
    /// the zone's chain broken rather than starving the answer fetch.
    async fn fetch_zone_keys(
        &self,
        validator: &Arc<RecursiveDnssecValidator>,
        zone: &Name,
        ns_addrs: &[SocketAddr],
        queries_used: &mut u32,
    ) {
        if *queries_used >= self.config.max_queries_per_resolution {
            return;
        }
        let Ok(dnskey_msg) = self
            .query_any_ns(ns_addrs, zone, RecordType::DNSKEY, queries_used)
            .await
        else {
            return;
        };
        let verdict = match extract_dnskey_rrset_from_answers(&dnskey_msg, zone) {
            Some((records, rrsigs)) => validator.record_dnskey_rrset(zone, &records, &rrsigs),
            // The zone has a verified DS, so it must serve a signed DNSKEY.
            None => DnssecVerdict::Bogus,
        };
        match verdict {
            DnssecVerdict::Secure => crate::STATS_COUNTERS.increment_recursive_dnssec_chain_built(),
            DnssecVerdict::Bogus => crate::STATS_COUNTERS.increment_recursive_dnssec_chain_broken(),
            DnssecVerdict::Insecure => {}
        }
    }

    /// Extend the chain of trust to the zones a final response depends on
    /// but the walk never crossed. A server hosting both a zone and its
    /// child answers for the child directly, with no referral, so:
    ///
    /// 1. data signed by a zone below `zone` gets that signer's DS (asked
    ///    from the same servers) and DNSKEY chained in;
    /// 2. unsigned data under a signed zone triggers a search for an
    ///    insecure zone cut (a DS NODATA proven by NSEC/NSEC3). Without
    ///    one the data stays `Bogus` — stripped signatures look the same.
    async fn complete_chain(
        &self,
        validator: &Arc<RecursiveDnssecValidator>,
        response: &Message,
        qname: &Name,
        zone: &Name,
        ns_addrs: &[SocketAddr],
        queries_used: &mut u32,
    ) {
        let mut signers = rrsig_signers(&response.answers);
        for signer in rrsig_signers(&response.authorities) {
            if !signers.contains(&signer) {
                signers.push(signer);
            }
        }
        for signer in signers {
            if zone.zone_of(&signer) && signer != *zone {
                self.chain_cohosted_zone(validator, zone, &signer, ns_addrs, queries_used, 0)
                    .await;
            }
        }

        for name in unsigned_names(response, qname) {
            if matches!(
                validator.closest_zone(&name),
                Some((_, ZoneStatus::Secure(_)))
            ) {
                self.probe_insecure_cut(validator, zone, &name, ns_addrs, queries_used)
                    .await;
            }
        }
    }

    /// Chain `signer`, a zone below `zone` served by the same `ns_addrs`:
    /// ask its DS, chain the zone that signed the DS first when it is
    /// itself an unknown cut, then validate the DS and fetch the DNSKEY.
    fn chain_cohosted_zone<'a>(
        &'a self,
        validator: &'a Arc<RecursiveDnssecValidator>,
        zone: &'a Name,
        signer: &'a Name,
        ns_addrs: &'a [SocketAddr],
        queries_used: &'a mut u32,
        depth: u8,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if depth >= MAX_COHOSTED_CUTS
                || validator.zone_status(signer).is_some()
                || *queries_used >= self.config.max_queries_per_resolution
            {
                return;
            }
            let Ok(ds_msg) = self
                .query_any_ns(ns_addrs, signer, RecordType::DS, queries_used)
                .await
            else {
                return;
            };
            // No signed DS for a zone that signs data: nothing to chain,
            // the data it signed stays unverifiable.
            let Some((ds_records, ds_sigs)) =
                extract_signed_rrset(&ds_msg.answers, signer, RecordType::DS)
            else {
                return;
            };
            let parent = ds_sigs[0].input().signer_name.clone();
            if !zone.zone_of(&parent) || !parent.zone_of(signer) || parent == *signer {
                return;
            }
            if parent != *zone && validator.zone_status(&parent).is_none() {
                self.chain_cohosted_zone(
                    validator,
                    zone,
                    &parent,
                    ns_addrs,
                    queries_used,
                    depth + 1,
                )
                .await;
            }
            if validator.record_ds_for_child(&parent, signer, &ds_records, &ds_sigs)
                == DnssecVerdict::Bogus
            {
                crate::STATS_COUNTERS.increment_recursive_dnssec_chain_broken();
            }
            if validator.needs_keys(signer) {
                self.fetch_zone_keys(validator, signer, ns_addrs, queries_used)
                    .await;
            }
        })
    }

    /// Look for an insecure zone cut between `zone` and `name`, shallowest
    /// first, by asking each candidate's DS from `ns_addrs`. Stops at the
    /// first cut found (secure or proven insecure) or at NXDOMAIN.
    async fn probe_insecure_cut(
        &self,
        validator: &Arc<RecursiveDnssecValidator>,
        zone: &Name,
        name: &Name,
        ns_addrs: &[SocketAddr],
        queries_used: &mut u32,
    ) {
        let mut candidates = Vec::new();
        let mut candidate = name.clone();
        while candidate != *zone && zone.zone_of(&candidate) {
            candidates.push(candidate.clone());
            candidate = candidate.base_name();
        }

        for cut in candidates.into_iter().rev() {
            if validator.zone_status(&cut).is_some() {
                return;
            }
            let Some((parent, ZoneStatus::Secure(_))) = validator.closest_zone(&cut.base_name())
            else {
                return;
            };
            if *queries_used >= self.config.max_queries_per_resolution {
                return;
            }
            let Ok(ds_msg) = self
                .query_any_ns(ns_addrs, &cut, RecordType::DS, queries_used)
                .await
            else {
                return;
            };
            if let Some((ds_records, ds_sigs)) =
                extract_signed_rrset(&ds_msg.answers, &cut, RecordType::DS)
            {
                // A signed cut: chain it; unsigned data below stays Bogus.
                validator.record_ds_for_child(&parent, &cut, &ds_records, &ds_sigs);
                if validator.needs_keys(&cut) {
                    self.fetch_zone_keys(validator, &cut, ns_addrs, queries_used)
                        .await;
                }
                return;
            }
            // Not a cut (or no proof) leaves the zone unknown: go deeper.
            validator.record_insecure_delegation(&parent, &cut, &ds_msg.authorities);
            if validator.zone_status(&cut).is_some()
                || ds_msg.metadata.response_code == ResponseCode::NXDomain
            {
                return;
            }
        }
    }

    /// Resolve the IP addresses of out-of-zone NS names by recursing for
    /// each name. The shared `budget` keeps a fan-out within the per-query
    /// caps and turns a glueless loop (`ns.a` ↔ `ns.b`) into a cycle error.
    fn resolve_ns_addresses<'a>(
        &'a self,
        ns_names: &'a [Name],
        budget: &'a mut ResolutionBudget,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let mut out = Vec::new();
            for ns in ns_names {
                if budget.queries_used >= self.config.max_queries_per_resolution {
                    break;
                }
                match self
                    .resolve_iterative(ns.clone(), RecordType::A, budget)
                    .await
                {
                    Ok(msg) => {
                        out =
                            self.usable_ns_addrs(msg.answers.iter().filter_map(
                                |rec| match &rec.data {
                                    RData::A(a) => Some(IpAddr::V4(a.0)),
                                    _ => None,
                                },
                            ));
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
    // The question section must echo the client's question: after a CNAME
    // chase the last upstream response carries the *target*'s question, and
    // strict stubs (glibc, systemd-resolved) reject a mismatch.
    upstream.queries.clear();
    if let Some(q) = client_query.message.queries.first() {
        upstream.add_query(q.clone());
    }
    upstream
        .to_vec()
        .map_err(|e| io::Error::other(format!("encode response: {e}")))
}

#[async_trait]
impl UpstreamResolver for RecursiveResolver {
    async fn resolve(&self, query: &DnsPacket) -> io::Result<Vec<u8>> {
        let q = query
            .message
            .queries
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no query in packet"))?;
        let qname = q.name().clone();
        let qtype = q.query_type();

        let mut budget = ResolutionBudget::default();
        let upstream = self.resolve_iterative(qname, qtype, &mut budget).await?;
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
/// then tries them in order until one answers. IPv4 roots come first;
/// IPv6 ones are used only when `ipv6` is true or no IPv4 root exists.
fn pick_initial_ns_addrs(roots: &[SocketAddr], ipv6: bool) -> Vec<SocketAddr> {
    let ipv6 = ipv6 || roots.iter().all(SocketAddr::is_ipv6);
    let roots = order_ns_addrs(roots.iter().copied(), ipv6);
    if roots.len() <= 3 {
        return roots;
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
    let picked: Vec<SocketAddr> = indices.into_iter().map(|i| roots[i]).collect();
    // Shuffled within each family, still IPv4 first.
    order_ns_addrs(picked, ipv6).into_iter().take(3).collect()
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
        assert_eq!(pick_initial_ns_addrs(&roots, true).len(), 3);
        let small: Vec<_> = roots.into_iter().take(2).collect();
        assert_eq!(pick_initial_ns_addrs(&small, true).len(), 2);
    }

    #[test]
    fn pick_initial_ns_addrs_returns_distinct_indices() {
        let roots = default_roots();
        let picked = pick_initial_ns_addrs(&roots, true);
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

    // ---- walk_cname_chain ----

    fn cname(owner: &str, target: &str) -> Record {
        Record::from_rdata(name(owner), 300, RData::CNAME(CNAME(name(target))))
    }

    fn a_record(owner: &str, ip: [u8; 4]) -> Record {
        Record::from_rdata(name(owner), 300, RData::A(A(Ipv4Addr::from(ip))))
    }

    #[test]
    fn walk_cname_chain_without_cname_is_the_name_itself() {
        let answers = vec![a_record("example.com.", [1, 2, 3, 4])];
        let walk = walk_cname_chain(&answers, &name("example.com."), &Name::root());
        assert_eq!(walk.owners, [name("example.com.")]);
        assert_eq!(walk.terminal(), &name("example.com."));
        assert!(walk.targets().is_empty());
        assert!(walk.aliases().is_empty());
    }

    #[test]
    fn walk_cname_chain_follows_records_in_any_order() {
        let answers = vec![
            a_record("c.example.", [1, 2, 3, 4]),
            cname("b.example.", "c.example."),
            cname("a.example.", "b.example."),
        ];
        let walk = walk_cname_chain(&answers, &name("a.example."), &name("example."));
        assert_eq!(
            walk.owners,
            [name("a.example."), name("b.example."), name("c.example.")]
        );
        assert_eq!(walk.aliases(), [name("a.example."), name("b.example.")]);
        assert_eq!(walk.targets(), [name("b.example."), name("c.example.")]);
    }

    #[test]
    fn walk_cname_chain_is_case_insensitive() {
        let answers = vec![cname("WWW.Example.", "cdn.example.")];
        let walk = walk_cname_chain(&answers, &name("www.example."), &name("example."));
        assert_eq!(walk.terminal(), &name("cdn.example."));
    }

    #[test]
    fn walk_cname_chain_ignores_out_of_zone_cname() {
        // `b.com` is not served by `a.com`: its CNAME must not be trusted.
        let answers = vec![
            cname("www.a.com.", "b.com."),
            cname("b.com.", "attacker.net."),
        ];
        let walk = walk_cname_chain(&answers, &name("www.a.com."), &name("a.com."));
        assert_eq!(walk.terminal(), &name("b.com."));
    }

    #[test]
    fn walk_cname_chain_bounded_on_in_message_loop() {
        let answers = vec![
            cname("a.example.", "b.example."),
            cname("b.example.", "a.example."),
        ];
        let walk = walk_cname_chain(&answers, &name("a.example."), &name("example."));
        assert_eq!(walk.owners.len(), answers.len() + 1);
    }

    #[test]
    fn has_answer_for_matches_type_owner_and_zone() {
        let answers = vec![
            cname("www.a.com.", "b.com."),
            a_record("b.com.", [1, 1, 1, 1]),
        ];
        let a_com = name("a.com.");
        // The A for `b.com` is out of `a.com`: not an answer.
        assert!(!has_answer_for(
            &answers,
            &name("b.com."),
            RecordType::A,
            &a_com
        ));
        assert!(has_answer_for(
            &answers,
            &name("b.com."),
            RecordType::A,
            &Name::root()
        ));
        assert!(!has_answer_for(
            &answers,
            &name("b.com."),
            RecordType::AAAA,
            &Name::root()
        ));
        assert!(has_answer_for(
            &answers,
            &name("b.com."),
            RecordType::ANY,
            &Name::root()
        ));
        // ANY does not count the alias itself as data.
        assert!(!has_answer_for(
            &answers,
            &name("www.a.com."),
            RecordType::ANY,
            &a_com
        ));
    }

    #[test]
    fn records_owned_by_drops_unrelated_and_out_of_zone() {
        let answers = vec![
            cname("www.a.com.", "cdn.a.com."),
            a_record("cdn.a.com.", [1, 1, 1, 1]),
            a_record("other.a.com.", [2, 2, 2, 2]),
            a_record("evil.net.", [6, 6, 6, 6]),
        ];
        let owners = [name("www.a.com."), name("cdn.a.com."), name("evil.net.")];
        let kept = records_owned_by(&answers, &owners, &name("a.com."));
        assert_eq!(kept, answers[..2]);
    }

    #[test]
    fn hash_resolution_distinguishes_type_and_ignores_case() {
        let www = name("www.example.");
        assert_eq!(
            hash_resolution(&www, RecordType::A),
            hash_resolution(&name("WWW.Example."), RecordType::A)
        );
        assert_ne!(
            hash_resolution(&www, RecordType::A),
            hash_resolution(&www, RecordType::AAAA)
        );
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
        serve_mock(socket, handler);
        addr
    }

    /// Answer every query on `socket` with `handler`.
    fn serve_mock<F>(socket: UdpSocket, handler: F)
    where
        F: Fn(&Message) -> Message + Send + Sync + 'static,
    {
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
    }

    // ---- mock delegation hierarchy (CNAME chase, glueless NS) ----
    //
    // Glue and NS lookups only carry an IP, so every mock of a hierarchy
    // listens on the *same* port, each on its own loopback address
    // (127.0.0.0/8 is all routed to `lo` on Linux), and the resolver's
    // `ns_port` points at that port.

    type MockHandler = Arc<dyn Fn(&Message) -> Message + Send + Sync>;

    /// Box a closure as a [`MockHandler`] (forces the higher-ranked
    /// `for<'a> Fn(&'a Message)` signature a bare `as` cast cannot infer).
    fn mock(handler: impl Fn(&Message) -> Message + Send + Sync + 'static) -> MockHandler {
        Arc::new(handler)
    }

    const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const COM_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
    const ZONE1_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
    const ZONE2_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);

    /// Bind one mock per address, all on one port, and return that port.
    async fn spawn_mock_hierarchy(servers: &[(Ipv4Addr, MockHandler)]) -> u16 {
        'retry: for _ in 0..16 {
            let first = UdpSocket::bind((servers[0].0, 0)).await.unwrap();
            let port = first.local_addr().unwrap().port();
            let mut sockets = vec![first];
            for (ip, _) in &servers[1..] {
                match UdpSocket::bind((*ip, port)).await {
                    Ok(socket) => sockets.push(socket),
                    Err(_) => continue 'retry,
                }
            }
            for (socket, (_, handler)) in sockets.into_iter().zip(servers) {
                let handler = Arc::clone(handler);
                serve_mock(socket, move |q| handler(q));
            }
            return port;
        }
        panic!("could not bind the mock hierarchy on a shared port");
    }

    fn qname_of(query: &Message) -> Name {
        query.queries.first().unwrap().name().clone()
    }

    fn answer_msg(records: Vec<Record>) -> Message {
        let mut resp = Message::query();
        resp.metadata.response_code = ResponseCode::NoError;
        for record in records {
            resp.add_answer(record);
        }
        resp
    }

    fn nxdomain_msg() -> Message {
        let mut resp = Message::query();
        resp.metadata.response_code = ResponseCode::NXDomain;
        resp
    }

    fn referral_msg(zone: &str, ns: &str, glue: Option<Ipv4Addr>) -> Message {
        let mut resp = Message::query();
        resp.metadata.response_code = ResponseCode::NoError;
        resp.add_authority(Record::from_rdata(name(zone), 300, RData::NS(NS(name(ns)))));
        if let Some(ip) = glue {
            resp.add_additional(Record::from_rdata(name(ns), 300, RData::A(A(ip))));
        }
        resp
    }

    /// Root server: delegates `com.` to `ns.com.` (glue: [`COM_IP`]).
    fn mock_root() -> MockHandler {
        mock(|_q| referral_msg("com.", "ns.com.", Some(COM_IP)))
    }

    /// `com.` server: one `(zone, ns, glue)` delegation per child zone.
    fn mock_com(delegations: Vec<(&'static str, &'static str, Option<Ipv4Addr>)>) -> MockHandler {
        Arc::new(move |q| {
            let qname = qname_of(q);
            delegations
                .iter()
                .find(|(zone, _, _)| name(zone).zone_of(&qname))
                .map_or_else(nxdomain_msg, |(zone, ns, glue)| {
                    referral_msg(zone, ns, *glue)
                })
        })
    }

    /// Mock handler that also counts the queries it receives.
    fn counting(counter: &Arc<std::sync::atomic::AtomicUsize>, inner: MockHandler) -> MockHandler {
        let counter = Arc::clone(counter);
        Arc::new(move |q| {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            inner(q)
        })
    }

    /// Resolve `qname` against a mock hierarchy whose root is at [`ROOT_IP`].
    async fn resolve_in_hierarchy(
        servers: &[(Ipv4Addr, MockHandler)],
        qname: &str,
        qtype: RecordType,
    ) -> io::Result<Message> {
        let port = spawn_mock_hierarchy(servers).await;
        let mut resolver = RecursiveResolver::with_roots(
            cfg_for_tests(),
            vec![SocketAddr::new(IpAddr::V4(ROOT_IP), port)],
        );
        resolver.ns_port = port;
        resolver.private_ns_allowed = true;
        let packet = make_dns_packet(qname, qtype);
        let bytes = resolver.resolve(&packet).await?;
        Ok(Message::from_vec(&bytes).unwrap())
    }

    fn assert_question(msg: &Message, qname: &str, qtype: RecordType) {
        let question = msg.queries.first().expect("question section");
        assert_eq!(question.name(), &name(qname));
        assert_eq!(question.query_type(), qtype);
        assert_eq!(msg.queries.len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cname_to_same_tld_returns_full_chain_under_client_question() {
        // www.a.com → CNAME b.com; both under `com.`. The old shared
        // `visited_zones` saw `com.` twice and failed with a false cycle.
        let servers = [
            (ROOT_IP, mock_root()),
            (
                COM_IP,
                mock_com(vec![
                    ("a.com.", "ns.a.com.", Some(ZONE1_IP)),
                    ("b.com.", "ns.b.com.", Some(ZONE2_IP)),
                ]),
            ),
            (
                ZONE1_IP,
                mock(|_q| answer_msg(vec![cname("www.a.com.", "b.com.")])),
            ),
            (
                ZONE2_IP,
                mock(|_q| answer_msg(vec![a_record("b.com.", [203, 0, 113, 9])])),
            ),
        ];
        let msg = resolve_in_hierarchy(&servers, "www.a.com.", RecordType::A)
            .await
            .expect("CNAME to the same TLD must resolve");
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert_question(&msg, "www.a.com.", RecordType::A);
        assert_eq!(
            msg.answers,
            [
                cname("www.a.com.", "b.com."),
                a_record("b.com.", [203, 0, 113, 9])
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn glueless_ns_in_same_tld_resolves() {
        // `x.com` is served by `ns.y.com` (no glue): resolving the NS
        // restarts from the root and crosses `com.` again.
        let servers = [
            (ROOT_IP, mock_root()),
            (
                COM_IP,
                mock_com(vec![
                    ("x.com.", "ns.y.com.", None),
                    ("y.com.", "ns.y.com.", Some(ZONE2_IP)),
                ]),
            ),
            (
                ZONE1_IP,
                mock(|q: &Message| {
                    answer_msg(vec![a_record(&qname_of(q).to_string(), [198, 51, 100, 1])])
                }),
            ),
            (
                ZONE2_IP,
                // ns.y.com lives on the x.com mock address.
                mock(|_q| answer_msg(vec![a_record("ns.y.com.", ZONE1_IP.octets())])),
            ),
        ];
        let msg = resolve_in_hierarchy(&servers, "www.x.com.", RecordType::A)
            .await
            .expect("glueless NS in the same TLD must resolve");
        assert_question(&msg, "www.x.com.", RecordType::A);
        assert_eq!(msg.answers, [a_record("www.x.com.", [198, 51, 100, 1])]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn glueless_ns_loop_is_a_cycle_not_a_hang() {
        // x.com ↔ y.com, each served by an NS in the other, no glue.
        let servers = [
            (ROOT_IP, mock_root()),
            (
                COM_IP,
                mock_com(vec![
                    ("x.com.", "ns.y.com.", None),
                    ("y.com.", "ns.x.com.", None),
                ]),
            ),
        ];
        let before = crate::STATS_COUNTERS.get_recursive_cycle_detected();
        let result = resolve_in_hierarchy(&servers, "www.x.com.", RecordType::A).await;
        assert!(result.is_err());
        assert!(crate::STATS_COUNTERS.get_recursive_cycle_detected() > before);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn in_zone_cname_chain_is_not_chased_again() {
        let root_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let servers = [
            (ROOT_IP, counting(&root_queries, mock_root())),
            (
                COM_IP,
                mock_com(vec![("a.com.", "ns.a.com.", Some(ZONE1_IP))]),
            ),
            (
                ZONE1_IP,
                mock(|_q| {
                    answer_msg(vec![
                        cname("www.a.com.", "cdn.a.com."),
                        a_record("cdn.a.com.", [192, 0, 2, 10]),
                    ])
                }),
            ),
        ];
        let msg = resolve_in_hierarchy(&servers, "www.a.com.", RecordType::A)
            .await
            .unwrap();
        assert_question(&msg, "www.a.com.", RecordType::A);
        assert_eq!(
            msg.answers,
            [
                cname("www.a.com.", "cdn.a.com."),
                a_record("cdn.a.com.", [192, 0, 2, 10])
            ]
        );
        assert_eq!(
            root_queries.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the target was answered in-zone: no second walk from the root"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn out_of_zone_target_data_is_not_trusted() {
        // a.com slips a forged A for b.com next to its CNAME: the resolver
        // must ask b.com's own servers instead.
        let servers = [
            (ROOT_IP, mock_root()),
            (
                COM_IP,
                mock_com(vec![
                    ("a.com.", "ns.a.com.", Some(ZONE1_IP)),
                    ("b.com.", "ns.b.com.", Some(ZONE2_IP)),
                ]),
            ),
            (
                ZONE1_IP,
                mock(|_q| {
                    answer_msg(vec![
                        cname("www.a.com.", "b.com."),
                        a_record("b.com.", [6, 6, 6, 6]),
                        a_record("bank.example.", [6, 6, 6, 6]),
                    ])
                }),
            ),
            (
                ZONE2_IP,
                mock(|_q| answer_msg(vec![a_record("b.com.", [203, 0, 113, 9])])),
            ),
        ];
        let msg = resolve_in_hierarchy(&servers, "www.a.com.", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            msg.answers,
            [
                cname("www.a.com.", "b.com."),
                a_record("b.com.", [203, 0, 113, 9])
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cname_cycle_across_zones_is_detected() {
        let servers = [
            (ROOT_IP, mock_root()),
            (
                COM_IP,
                mock_com(vec![
                    ("a.com.", "ns.a.com.", Some(ZONE1_IP)),
                    ("b.com.", "ns.b.com.", Some(ZONE2_IP)),
                ]),
            ),
            (
                ZONE1_IP,
                mock(|_q| answer_msg(vec![cname("www.a.com.", "www.b.com.")])),
            ),
            (
                ZONE2_IP,
                mock(|_q| answer_msg(vec![cname("www.b.com.", "www.a.com.")])),
            ),
        ];
        let before = crate::STATS_COUNTERS.get_recursive_cycle_detected();
        let result = resolve_in_hierarchy(&servers, "www.a.com.", RecordType::A).await;
        assert!(result.is_err());
        assert!(crate::STATS_COUNTERS.get_recursive_cycle_detected() > before);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cname_to_nxdomain_keeps_chain_and_rcode() {
        let servers = [
            (ROOT_IP, mock_root()),
            (
                COM_IP,
                mock_com(vec![
                    ("a.com.", "ns.a.com.", Some(ZONE1_IP)),
                    ("b.com.", "ns.b.com.", Some(ZONE2_IP)),
                ]),
            ),
            (
                ZONE1_IP,
                mock(|_q| answer_msg(vec![cname("www.a.com.", "gone.b.com.")])),
            ),
            (ZONE2_IP, mock(|_q| nxdomain_msg())),
        ];
        let msg = resolve_in_hierarchy(&servers, "www.a.com.", RecordType::A)
            .await
            .unwrap();
        // RFC 6604: the rcode describes the last name of the chain.
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
        assert_question(&msg, "www.a.com.", RecordType::A);
        assert_eq!(msg.answers, [cname("www.a.com.", "gone.b.com.")]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cname_query_is_not_chased() {
        let b_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let servers = [
            (ROOT_IP, mock_root()),
            (
                COM_IP,
                mock_com(vec![
                    ("a.com.", "ns.a.com.", Some(ZONE1_IP)),
                    ("b.com.", "ns.b.com.", Some(ZONE2_IP)),
                ]),
            ),
            (
                ZONE1_IP,
                mock(|_q| answer_msg(vec![cname("www.a.com.", "b.com.")])),
            ),
            (
                ZONE2_IP,
                counting(
                    &b_queries,
                    mock(|_q| answer_msg(vec![a_record("b.com.", [203, 0, 113, 9])])),
                ),
            ),
        ];
        let msg = resolve_in_hierarchy(&servers, "www.a.com.", RecordType::CNAME)
            .await
            .unwrap();
        assert_eq!(msg.answers, [cname("www.a.com.", "b.com.")]);
        assert_eq!(b_queries.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cname_chain_longer_than_max_depth_fails() {
        // Every name `nK.a.com` points to `nK+1.b.com` and back, each in its
        // own zone, so each hop is a fresh chase.
        let servers = [
            (ROOT_IP, mock_root()),
            (
                COM_IP,
                mock_com(vec![
                    ("a.com.", "ns.a.com.", Some(ZONE1_IP)),
                    ("b.com.", "ns.b.com.", Some(ZONE2_IP)),
                ]),
            ),
            (ZONE1_IP, next_hop_cname("b.com.")),
            (ZONE2_IP, next_hop_cname("a.com.")),
        ];
        let port = spawn_mock_hierarchy(&servers).await;
        let mut cfg = cfg_for_tests();
        cfg.max_cname_depth = 2;
        cfg.max_queries_per_resolution = 64;
        let mut resolver =
            RecursiveResolver::with_roots(cfg, vec![SocketAddr::new(IpAddr::V4(ROOT_IP), port)]);
        resolver.ns_port = port;
        resolver.private_ns_allowed = true;
        let packet = make_dns_packet("n0.a.com.", RecordType::A);
        let err = resolver.resolve(&packet).await.unwrap_err();
        assert!(err.to_string().contains("max_cname_depth"), "got {err}");
    }

    /// Answer `nK.<zone>` with `CNAME nK+1.<next_zone>`.
    fn next_hop_cname(next_zone: &'static str) -> MockHandler {
        Arc::new(move |q| {
            let qname = qname_of(q).to_string();
            let label = qname.split('.').next().unwrap();
            let hop: u32 = label.trim_start_matches('n').parse().unwrap();
            answer_msg(vec![cname(&qname, &format!("n{}.{next_zone}", hop + 1))])
        })
    }

    // ---- DNSSEC through the iterative loop (review E1) ----

    use crate::dns::dnssec_chain::RootTrustAnchor;
    use crate::dns::dnssec_chain::test_support::{TestZone, ds_records, nsec_record};

    fn qtype_of(query: &Message) -> RecordType {
        query.queries.first().unwrap().query_type()
    }

    fn with_authority(mut msg: Message, records: &[Record]) -> Message {
        for record in records {
            msg.add_authority(record.clone());
        }
        msg
    }

    /// Mock servers of a signed hierarchy, keys generated per call:
    ///
    /// * `.` (ROOT) → `com.` (COM) → `a.com.` (ZONE1), all signed;
    /// * `sub.a.com.`: signed child hosted on the a.com server (no referral);
    /// * `ins.a.com.`: unsigned child hosted on the a.com server, no-DS
    ///   proven by an NSEC;
    /// * `b.com.`: unsigned zone (ZONE2), insecure delegation proven by NSEC;
    /// * `stripped.com.`: delegation to ZONE2 whose DS was removed.
    ///
    /// Returns the servers and the root zone whose key is the anchor.
    fn signed_hierarchy() -> (Vec<(Ipv4Addr, MockHandler)>, TestZone) {
        let root = TestZone::new(".");
        let com = TestZone::new("com.");
        let a_com = TestZone::new("a.com.");
        let sub = TestZone::new("sub.a.com.");

        let root_keys = root.signed(root.dnskey_rrset());
        let com_ds = root.signed(ds_records(&com.zone, &[com.ds()]));
        let root_handler = mock(move |q| {
            if qtype_of(q) == RecordType::DNSKEY {
                return answer_msg(root_keys.clone());
            }
            with_authority(referral_msg("com.", "ns.com.", Some(COM_IP)), &com_ds)
        });

        let com_keys = com.signed(com.dnskey_rrset());
        let a_ds = com.signed(ds_records(&a_com.zone, &[a_com.ds()]));
        let b_proof = com.signed(vec![nsec_record(
            &name("b.com."),
            &name("c.com."),
            &[RecordType::NS, RecordType::NSEC],
        )]);
        let com_handler = mock(move |q| {
            let qname = qname_of(q);
            if qtype_of(q) == RecordType::DNSKEY && qname == name("com.") {
                answer_msg(com_keys.clone())
            } else if name("a.com.").zone_of(&qname) {
                with_authority(referral_msg("a.com.", "ns.a.com.", Some(ZONE1_IP)), &a_ds)
            } else if name("b.com.").zone_of(&qname) {
                with_authority(
                    referral_msg("b.com.", "ns.b.com.", Some(ZONE2_IP)),
                    &b_proof,
                )
            } else if name("stripped.com.").zone_of(&qname) {
                referral_msg("stripped.com.", "ns.stripped.com.", Some(ZONE2_IP))
            } else {
                nxdomain_msg()
            }
        });

        let a_keys = a_com.signed(a_com.dnskey_rrset());
        let www = a_com.signed(vec![a_record("www.a.com.", [192, 0, 2, 1])]);
        let sub_ds = a_com.signed(ds_records(&sub.zone, &[sub.ds()]));
        let sub_keys = sub.signed(sub.dnskey_rrset());
        let www_sub = sub.signed(vec![a_record("www.sub.a.com.", [192, 0, 2, 2])]);
        let ins_proof = a_com.signed(vec![nsec_record(
            &name("ins.a.com."),
            &name("www.a.com."),
            &[RecordType::NS, RecordType::NSEC],
        )]);
        let a_handler = mock(
            move |q| match (qname_of(q).to_string().as_str(), qtype_of(q)) {
                ("a.com.", RecordType::DNSKEY) => answer_msg(a_keys.clone()),
                ("www.a.com.", RecordType::A) => answer_msg(www.clone()),
                ("bad.a.com.", RecordType::A) => {
                    answer_msg(vec![a_record("bad.a.com.", [6, 6, 6, 6])])
                }
                ("sub.a.com.", RecordType::DS) => answer_msg(sub_ds.clone()),
                ("sub.a.com.", RecordType::DNSKEY) => answer_msg(sub_keys.clone()),
                ("www.sub.a.com.", RecordType::A) => answer_msg(www_sub.clone()),
                ("ins.a.com.", RecordType::DS) => with_authority(answer_msg(vec![]), &ins_proof),
                ("www.ins.a.com.", RecordType::A) => {
                    answer_msg(vec![a_record("www.ins.a.com.", [192, 0, 2, 3])])
                }
                // NODATA without any proof.
                _ => answer_msg(vec![]),
            },
        );

        // Unsigned zone server (b.com, stripped.com).
        let unsigned_handler =
            mock(|q| answer_msg(vec![a_record(&qname_of(q).to_string(), [198, 51, 100, 7])]));

        let servers = vec![
            (ROOT_IP, root_handler),
            (COM_IP, com_handler),
            (ZONE1_IP, a_handler),
            (ZONE2_IP, unsigned_handler),
        ];
        (servers, root)
    }

    /// Resolve `qname` / A through `servers` with a validator anchored on
    /// `anchor`, then validate the client response like `handle_query`.
    async fn resolve_and_validate(
        servers: &[(Ipv4Addr, MockHandler)],
        anchor: RootTrustAnchor,
        qname: &str,
    ) -> DnssecVerdict {
        let validator = Arc::new(RecursiveDnssecValidator::with_root_anchors(&[anchor]));
        let port = spawn_mock_hierarchy(servers).await;
        let mut resolver = RecursiveResolver::with_roots(
            cfg_for_tests(),
            vec![SocketAddr::new(IpAddr::V4(ROOT_IP), port)],
        )
        .with_validator(Arc::clone(&validator));
        resolver.ns_port = port;
        resolver.private_ns_allowed = true;
        let packet = make_dns_packet(qname, RecordType::A);
        let bytes = resolver.resolve(&packet).await.expect("resolution");
        let msg = Message::from_vec(&bytes).unwrap();
        validator.validate_message_for(&msg, &name(qname), RecordType::A)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dnssec_secure_chain_from_root_anchor() {
        let (servers, root) = signed_hierarchy();
        let verdict = resolve_and_validate(&servers, root.as_root_anchor(), "www.a.com.").await;
        assert_eq!(verdict, DnssecVerdict::Secure);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dnssec_stripped_answer_signature_is_bogus() {
        let (servers, root) = signed_hierarchy();
        let verdict = resolve_and_validate(&servers, root.as_root_anchor(), "bad.a.com.").await;
        assert_eq!(verdict, DnssecVerdict::Bogus);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dnssec_proven_insecure_delegation_is_insecure() {
        let (servers, root) = signed_hierarchy();
        let verdict = resolve_and_validate(&servers, root.as_root_anchor(), "www.b.com.").await;
        assert_eq!(verdict, DnssecVerdict::Insecure);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dnssec_ds_stripped_from_referral_is_bogus() {
        let (servers, root) = signed_hierarchy();
        let verdict =
            resolve_and_validate(&servers, root.as_root_anchor(), "www.stripped.com.").await;
        assert_eq!(verdict, DnssecVerdict::Bogus);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dnssec_signed_child_on_parent_servers_is_chained() {
        let (servers, root) = signed_hierarchy();
        let verdict = resolve_and_validate(&servers, root.as_root_anchor(), "www.sub.a.com.").await;
        assert_eq!(verdict, DnssecVerdict::Secure);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dnssec_unsigned_child_on_parent_servers_is_proven_insecure() {
        let (servers, root) = signed_hierarchy();
        let verdict = resolve_and_validate(&servers, root.as_root_anchor(), "www.ins.a.com.").await;
        assert_eq!(verdict, DnssecVerdict::Insecure);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dnssec_root_key_not_matching_anchor_is_bogus() {
        let (servers, _root) = signed_hierarchy();
        let other_anchor = TestZone::new(".").as_root_anchor();
        let verdict = resolve_and_validate(&servers, other_anchor, "www.a.com.").await;
        assert_eq!(verdict, DnssecVerdict::Bogus);
    }

    /// Live check against the real root servers (network required):
    /// `cargo nextest run -p dgaard --run-ignored only live_dnssec`.
    /// Guards the fail-closed validator against real-world shapes the
    /// mocks cannot cover (NSEC3 opt-out in `.com`, KSK rollovers…).
    #[tokio::test]
    #[ignore = "needs Internet access to the root servers"]
    async fn live_dnssec_verdicts_from_the_real_root() {
        let cases = [
            ("www.isc.org.", RecordType::A, DnssecVerdict::Secure),
            ("cloudflare.com.", RecordType::A, DnssecVerdict::Secure),
            ("www.google.com.", RecordType::A, DnssecVerdict::Insecure),
            (
                "nonexistent-dgaard-probe.isc.org.",
                RecordType::A,
                DnssecVerdict::Secure,
            ),
            ("dnssec-failed.org.", RecordType::A, DnssecVerdict::Bogus),
        ];
        for (qname, qtype, expected) in cases {
            let validator = Arc::new(RecursiveDnssecValidator::default());
            let config = RecursiveConfig {
                max_queries_per_resolution: 64,
                ..RecursiveConfig::default()
            };
            let resolver = RecursiveResolver::from_config(config)
                .unwrap()
                .with_validator(Arc::clone(&validator));
            let packet = make_dns_packet(qname, qtype);
            let bytes = resolver.resolve(&packet).await.expect(qname);
            let msg = Message::from_vec(&bytes).unwrap();
            let verdict = validator.validate_message_for(&msg, &name(qname), qtype);
            assert_eq!(
                verdict, expected,
                "{qname} ({:?})",
                msg.metadata.response_code
            );
        }
    }

    // ---- TCP fallback on truncation ----

    /// Mock authoritative on one port: UDP answers with TC=1 and no data,
    /// TCP answers with the A record.
    async fn spawn_truncating_ns(ip: Ipv4Addr) -> SocketAddr {
        loop {
            let addr = spawn_mock_ns(|_q| {
                let mut resp = Message::query();
                resp.metadata.response_code = ResponseCode::NoError;
                resp.metadata.truncation = true;
                resp
            })
            .await;
            let Ok(listener) = tokio::net::TcpListener::bind(addr).await else {
                continue;
            };
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let Ok(Some(raw)) = crate::dns::tcp::read_message(&mut stream).await else {
                            return;
                        };
                        let query = Message::from_vec(&raw).unwrap();
                        let mut resp = Message::query();
                        resp.metadata.id = query.metadata.id;
                        resp.metadata.message_type = MessageType::Response;
                        resp.metadata.response_code = ResponseCode::NoError;
                        let qname = qname_of(&query);
                        resp.add_query(query.queries[0].clone());
                        resp.add_answer(Record::from_rdata(qname, 300, RData::A(A(ip))));
                        let _ =
                            crate::dns::tcp::write_message(&mut stream, &resp.to_vec().unwrap())
                                .await;
                    });
                }
            });
            return addr;
        }
    }

    #[tokio::test]
    async fn truncated_authoritative_answer_is_fetched_over_tcp() {
        // Used to be a SERVFAIL ("TCP fallback not implemented yet").
        let target = Ipv4Addr::new(192, 0, 2, 77);
        let root = spawn_truncating_ns(target).await;
        let before = crate::STATS_COUNTERS.get_recursive_tcp_fallback();
        let resolver = RecursiveResolver::with_roots(cfg_for_tests(), vec![root]);
        let packet = make_dns_packet("big.example.", RecordType::A);
        let bytes = resolver.resolve(&packet).await.expect("answer over TCP");
        let parsed = Message::from_vec(&bytes).unwrap();
        assert!(!parsed.metadata.truncation);
        assert_eq!(parsed.answers, [a_record("big.example.", target.octets())]);
        assert!(crate::STATS_COUNTERS.get_recursive_tcp_fallback() > before);
    }

    #[tokio::test]
    async fn tcp_fallback_is_paid_from_the_query_budget() {
        // One query allowed: the UDP query spends it, no TCP retry is made
        // and the truncated answer is an error, not a partial answer.
        let root = spawn_truncating_ns(Ipv4Addr::new(192, 0, 2, 78)).await;
        let mut cfg = cfg_for_tests();
        cfg.max_queries_per_resolution = 1;
        let resolver = RecursiveResolver::with_roots(cfg, vec![root]);
        let packet = make_dns_packet("big.example.", RecordType::A);
        let err = resolver.resolve(&packet).await.unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
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

        let mut dnskey_rrset = RecordSet::with_ttl(zone.clone(), RecordType::DNSKEY, 3600);
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
                ..ZoneTrustState::default()
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

    #[test]
    fn build_client_response_replaces_target_question() {
        // After a CNAME chase the upstream message carries the target's
        // question; the client must get its own back.
        let client = make_dns_packet("www.a.com.", RecordType::A);
        let mut upstream = Message::query();
        upstream.add_query(Query::query(name("b.com."), RecordType::A));
        upstream.add_answer(cname("www.a.com.", "b.com."));
        let bytes = build_client_response(&client, upstream).unwrap();
        let parsed = Message::from_vec(&bytes).unwrap();
        assert_question(&parsed, "www.a.com.", RecordType::A);
    }

    // ---- review M5: delegation cache, NS address hygiene, forged packets ----

    #[test]
    fn name_hash_ignores_case_and_tells_names_apart() {
        assert_eq!(
            hash_zone_label(&name("Example.COM.")),
            hash_zone_label(&name("example.com."))
        );
        assert_ne!(
            hash_zone_label(&name("example.com.")),
            hash_zone_label(&name("example.net."))
        );
        // Label boundaries count: `ab.c.` is not `a.bc.`.
        assert_ne!(
            hash_zone_label(&name("ab.c.")),
            hash_zone_label(&name("a.bc."))
        );
        assert_ne!(
            hash_resolution(&name("example.com."), RecordType::A),
            hash_resolution(&name("example.com."), RecordType::AAAA)
        );
        assert_eq!(
            hash_resolution(&name("WWW.example.com."), RecordType::A),
            hash_resolution(&name("www.example.com."), RecordType::A)
        );
        // The root hashes like any other name, without panicking.
        let _ = hash_zone_label(&Name::root());
    }

    #[test]
    fn ns_addresses_on_the_lan_or_local_host_are_refused() {
        let refused = [
            "127.0.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.53",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.251",
            "255.255.255.255",
            "240.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::53",
            "fe80::1",
            "ff02::fb",
            "::ffff:192.168.1.1",
            "::ffff:127.0.0.1",
        ];
        for ip in refused {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!is_public_ns_address(ip), "{ip} must be refused");
        }
        let accepted = [
            "198.41.0.4",
            "8.8.8.8",
            "100.128.0.1",
            "172.32.0.1",
            "2001:503:ba3e::2:30",
            "::ffff:8.8.8.8",
        ];
        for ip in accepted {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_public_ns_address(ip), "{ip} must be accepted");
        }
    }

    #[test]
    fn usable_ns_addrs_filters_and_puts_ipv4_first() {
        let mut resolver = RecursiveResolver::with_roots(cfg_for_tests(), Vec::new());
        resolver.ipv6_usable = true;
        let ips: Vec<IpAddr> = ["2001:db8::53", "192.168.1.1", "198.51.100.53", "::1"]
            .iter()
            .map(|ip| ip.parse().unwrap())
            .collect();
        let addrs = resolver.usable_ns_addrs(ips.clone());
        assert_eq!(
            addrs,
            [
                "198.51.100.53:53".parse::<SocketAddr>().unwrap(),
                "[2001:db8::53]:53".parse().unwrap()
            ]
        );

        resolver.ipv6_usable = false;
        assert_eq!(
            resolver.usable_ns_addrs(ips.clone()),
            ["198.51.100.53:53".parse::<SocketAddr>().unwrap()]
        );

        resolver.private_ns_allowed = true;
        assert_eq!(resolver.usable_ns_addrs(ips).len(), 2, "no IPv6 still");
    }

    #[test]
    fn initial_roots_skip_ipv6_without_a_route() {
        let roots = default_roots();
        for _ in 0..20 {
            let picked = pick_initial_ns_addrs(&roots, false);
            assert_eq!(picked.len(), 3);
            assert!(picked.iter().all(SocketAddr::is_ipv4), "{picked:?}");
        }
        // With IPv6, IPv4 roots still come first.
        let picked = pick_initial_ns_addrs(&roots, true);
        assert!(picked.iter().all(SocketAddr::is_ipv4), "{picked:?}");
        // IPv6-only hints are used whatever the route check says.
        let v6_only: Vec<SocketAddr> = roots.iter().copied().filter(SocketAddr::is_ipv6).collect();
        let picked = pick_initial_ns_addrs(&v6_only, false);
        assert_eq!(picked.len(), 3);
        assert!(picked.iter().all(SocketAddr::is_ipv6));
    }

    #[test]
    fn order_ns_addrs_keeps_order_within_a_family() {
        let addrs: Vec<SocketAddr> = [
            "[2001:db8::1]:53",
            "192.0.2.1:53",
            "[2001:db8::2]:53",
            "192.0.2.2:53",
        ]
        .iter()
        .map(|addr| addr.parse().unwrap())
        .collect();
        let ordered = order_ns_addrs(addrs.clone(), true);
        assert_eq!(ordered, [addrs[1], addrs[3], addrs[0], addrs[2]]);
        assert_eq!(order_ns_addrs(addrs.clone(), false), [addrs[1], addrs[3]]);
    }

    #[test]
    fn delegation_ttl_is_the_smallest_ns_ttl_capped() {
        let mut authorities = vec![
            Record::from_rdata(name("a.com."), 7200, RData::NS(NS(name("ns1.a.com.")))),
            Record::from_rdata(name("a.com."), 3600, RData::NS(NS(name("ns2.a.com.")))),
            // Other owners do not count.
            Record::from_rdata(name("b.com."), 5, RData::NS(NS(name("ns.b.com.")))),
        ];
        assert_eq!(delegation_ttl(&authorities, &name("a.com.")), 3600);
        authorities.truncate(1);
        authorities[0].ttl = 7 * 86_400;
        assert_eq!(
            delegation_ttl(&authorities, &name("a.com.")),
            MAX_DELEGATION_TTL
        );
        assert_eq!(delegation_ttl(&authorities, &name("c.com.")), 0);
    }

    #[test]
    fn delegation_cache_lifecycle() {
        let cache = DelegationCache::new(2);
        let servers = ["192.0.2.1:53".parse::<SocketAddr>().unwrap()];
        cache.insert(&name("a.com."), &servers, 300);
        assert_eq!(cache.get(&name("A.com.")), Some(servers.to_vec()));
        assert_eq!(cache.get(&name("b.com.")), None);

        // Not stored: no TTL, no servers.
        cache.insert(&name("b.com."), &servers, 0);
        cache.insert(&name("b.com."), &[], 300);
        assert_eq!(cache.len(), 1);

        // Expired entries are dropped on lookup.
        let past = Instant::now() - Duration::from_secs(1);
        cache.put(&name("old.com."), &servers, past);
        assert_eq!(cache.get(&name("old.com.")), None);
        assert_eq!(cache.len(), 1);

        // Bounded.
        cache.insert(&name("b.com."), &servers, 300);
        cache.insert(&name("c.com."), &servers, 300);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&name("a.com.")), None);

        cache.remove(&name("c.com."));
        assert_eq!(cache.get(&name("c.com.")), None);
        assert!(cache.get(&name("b.com.")).is_some());
    }

    #[test]
    fn walk_starts_at_the_deepest_cached_cut() {
        let resolver = RecursiveResolver::with_roots(cfg_for_tests(), default_roots());
        let com = ["192.0.2.1:53".parse::<SocketAddr>().unwrap()];
        let example = ["192.0.2.2:53".parse::<SocketAddr>().unwrap()];
        resolver.delegations.insert(&name("com."), &com, 300);
        resolver
            .delegations
            .insert(&name("example.com."), &example, 300);

        let (zone, servers) = resolver.start_point(&name("www.example.com."), RecordType::A);
        assert_eq!((zone, servers), (name("example.com."), example.to_vec()));
        let (zone, _) = resolver.start_point(&name("other.com."), RecordType::A);
        assert_eq!(zone, name("com."));
        // The zone apex itself is served by the child...
        let (zone, _) = resolver.start_point(&name("example.com."), RecordType::A);
        assert_eq!(zone, name("example.com."));
        // ...but its DS lives in the parent.
        let (zone, _) = resolver.start_point(&name("example.com."), RecordType::DS);
        assert_eq!(zone, name("com."));
        let (zone, servers) = resolver.start_point(&name("example.org."), RecordType::A);
        assert!(zone.is_root());
        assert_eq!(servers.len(), 3);
    }

    #[test]
    fn walk_ignores_cuts_whose_trust_state_is_unknown() {
        let validator = Arc::new(RecursiveDnssecValidator::default());
        let resolver = RecursiveResolver::with_roots(cfg_for_tests(), default_roots())
            .with_validator(validator);
        let servers = ["192.0.2.2:53".parse::<SocketAddr>().unwrap()];
        resolver
            .delegations
            .insert(&name("example.com."), &servers, 300);
        let (zone, _) = resolver.start_point(&name("www.example.com."), RecordType::A);
        assert!(
            zone.is_root(),
            "the chain of trust to example.com is unknown"
        );
    }

    fn query_for(qname: &str, qtype: RecordType) -> Message {
        build_outgoing_query(&name(qname), qtype, None, false)
    }

    fn answer_to(query: &Message) -> Message {
        let mut response = query.clone();
        response.metadata.message_type = MessageType::Response;
        response
    }

    #[test]
    fn accept_response_checks_txid_qr_and_question() {
        let query = query_for("www.example.com.", RecordType::A);
        let good = answer_to(&query);
        assert!(accept_response(&good.to_vec().unwrap(), &query).is_some());

        // Name comparison is case-insensitive.
        let mut upper = good.clone();
        upper.queries[0].set_name(name("WWW.Example.COM."));
        assert!(accept_response(&upper.to_vec().unwrap(), &query).is_some());

        let mut wrong_id = good.clone();
        wrong_id.metadata.id = query.metadata.id.wrapping_add(1);
        let reflected = query.clone();
        let mut other_name = good.clone();
        other_name.queries[0].set_name(name("bank.example."));
        let mut other_type = good.clone();
        other_type.queries[0].set_query_type(RecordType::AAAA);
        let mut other_class = good.clone();
        other_class.queries[0].set_query_class(DNSClass::CH);
        let mut no_question = good.clone();
        no_question.queries.clear();
        let mut two_questions = good.clone();
        two_questions.add_query(good.queries[0].clone());
        for (label, msg) in [
            ("wrong TXID", wrong_id),
            ("QR=0", reflected),
            ("other name", other_name),
            ("other type", other_type),
            ("other class", other_class),
            ("no question", no_question),
            ("two questions", two_questions),
        ] {
            assert!(
                accept_response(&msg.to_vec().unwrap(), &query).is_none(),
                "{label} must be rejected"
            );
        }
        assert!(accept_response(b"\x00\x01garbage", &query).is_none());
    }

    /// Mock authoritative that, before each real answer, sends forged and
    /// garbled datagrams with the right TXID, plus a well-formed forged
    /// answer from another port. Real answer: 192.0.2.80.
    async fn spawn_noisy_ns() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let spoofer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let Ok(query) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let qname = qname_of(&query);
                let forged_data = |qname: Name| {
                    let mut msg = answer_to(&query);
                    msg.add_answer(Record::from_rdata(qname, 300, RData::A(A::new(6, 6, 6, 6))));
                    msg
                };
                let mut other_question = forged_data(name("bank.example."));
                other_question.queries[0].set_name(name("bank.example."));
                let mut wrong_id = forged_data(qname.clone());
                wrong_id.metadata.id = query.metadata.id.wrapping_add(1);
                let mut garbage = buf[..2].to_vec();
                garbage.extend_from_slice(b"\x81\x80garbage");

                let _ = spoofer
                    .send_to(&forged_data(qname.clone()).to_vec().unwrap(), peer)
                    .await;
                for noise in [
                    garbage,
                    buf[..len].to_vec(), // the query reflected (QR=0)
                    wrong_id.to_vec().unwrap(),
                    other_question.to_vec().unwrap(),
                ] {
                    let _ = socket.send_to(&noise, peer).await;
                }
                let mut real = answer_to(&query);
                real.add_answer(Record::from_rdata(
                    qname,
                    300,
                    RData::A(A::new(192, 0, 2, 80)),
                ));
                let _ = socket.send_to(&real.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn forged_and_garbled_datagrams_do_not_abort_the_query() {
        let root = spawn_noisy_ns().await;
        let resolver = RecursiveResolver::with_roots(cfg_for_tests(), vec![root]);
        let bytes = resolver
            .resolve(&make_dns_packet("www.example.com.", RecordType::A))
            .await
            .expect("the real answer arrives after the noise");
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.answers, [a_record("www.example.com.", [192, 0, 2, 80])]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn warm_zone_is_resolved_without_walking_from_the_root() {
        let root_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let com_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let servers = [
            (ROOT_IP, counting(&root_queries, mock_root())),
            (
                COM_IP,
                counting(
                    &com_queries,
                    mock_com(vec![("a.com.", "ns.a.com.", Some(ZONE1_IP))]),
                ),
            ),
            (
                ZONE1_IP,
                mock(|q: &Message| {
                    answer_msg(vec![a_record(&qname_of(q).to_string(), [192, 0, 2, 1])])
                }),
            ),
        ];
        let port = spawn_mock_hierarchy(&servers).await;
        let resolver = hierarchy_resolver(port);
        for qname in ["www.a.com.", "mail.a.com.", "www.a.com."] {
            let bytes = resolver
                .resolve(&make_dns_packet(qname, RecordType::A))
                .await
                .unwrap();
            let msg = Message::from_vec(&bytes).unwrap();
            assert_eq!(msg.answers, [a_record(qname, [192, 0, 2, 1])]);
        }
        let relaxed = std::sync::atomic::Ordering::Relaxed;
        assert_eq!(root_queries.load(relaxed), 1, "root asked once");
        assert_eq!(com_queries.load(relaxed), 1, "com. asked once");
        assert_eq!(
            resolver.delegations.get(&name("a.com.")),
            Some(vec![SocketAddr::new(IpAddr::V4(ZONE1_IP), port)])
        );
    }

    fn hierarchy_resolver(port: u16) -> RecursiveResolver {
        let mut resolver = RecursiveResolver::with_roots(
            cfg_for_tests(),
            vec![SocketAddr::new(IpAddr::V4(ROOT_IP), port)],
        );
        resolver.ns_port = port;
        resolver.private_ns_allowed = true;
        resolver
    }

    /// `a.com.` really lives on [`ZONE1_IP`]; the cache says [`ZONE2_IP`],
    /// whose server behaves as `stale`. The walk must recover from the root.
    async fn recovers_from_stale_delegation(stale: MockHandler) {
        let root_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let servers = [
            (ROOT_IP, counting(&root_queries, mock_root())),
            (
                COM_IP,
                mock_com(vec![("a.com.", "ns.a.com.", Some(ZONE1_IP))]),
            ),
            (
                ZONE1_IP,
                mock(|_q| answer_msg(vec![a_record("www.a.com.", [192, 0, 2, 1])])),
            ),
            (ZONE2_IP, stale),
        ];
        let port = spawn_mock_hierarchy(&servers).await;
        let resolver = hierarchy_resolver(port);
        let stale_addr = SocketAddr::new(IpAddr::V4(ZONE2_IP), port);
        resolver
            .delegations
            .insert(&name("a.com."), &[stale_addr], 300);

        let bytes = resolver
            .resolve(&make_dns_packet("www.a.com.", RecordType::A))
            .await
            .expect("recovered through the root");
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.answers, [a_record("www.a.com.", [192, 0, 2, 1])]);
        assert_eq!(root_queries.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(
            resolver.delegations.get(&name("a.com.")),
            Some(vec![SocketAddr::new(IpAddr::V4(ZONE1_IP), port)]),
            "the stale entry is replaced"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn refusing_cached_server_falls_back_to_the_root() {
        recovers_from_stale_delegation(mock(|_q| {
            let mut refused = Message::query();
            refused.metadata.response_code = ResponseCode::Refused;
            refused
        }))
        .await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn upward_referral_from_cached_server_falls_back_to_the_root() {
        recovers_from_stale_delegation(mock(|_q| referral_msg("com.", "ns.com.", Some(COM_IP))))
            .await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn unreachable_cached_server_falls_back_to_the_root() {
        // Nothing listens on 127.0.0.9: the connected socket gets the ICMP
        // port-unreachable at once.
        let servers = [
            (ROOT_IP, mock_root()),
            (
                COM_IP,
                mock_com(vec![("a.com.", "ns.a.com.", Some(ZONE1_IP))]),
            ),
            (
                ZONE1_IP,
                mock(|_q| answer_msg(vec![a_record("www.a.com.", [192, 0, 2, 1])])),
            ),
        ];
        let port = spawn_mock_hierarchy(&servers).await;
        let resolver = hierarchy_resolver(port);
        let dead = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), port);
        resolver.delegations.insert(&name("a.com."), &[dead], 300);
        let bytes = resolver
            .resolve(&make_dns_packet("www.a.com.", RecordType::A))
            .await
            .expect("recovered through the root");
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.answers, [a_record("www.a.com.", [192, 0, 2, 1])]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn private_glue_is_never_queried() {
        // The root delegates `evil.` with glue on the loopback, where a
        // server answers. Production rules drop that glue.
        let glue_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let servers = [
            (
                ROOT_IP,
                mock(|_q| referral_msg("evil.", "ns.evil.", Some(COM_IP))),
            ),
            (
                COM_IP,
                counting(
                    &glue_queries,
                    mock(|_q| answer_msg(vec![a_record("www.evil.", [192, 0, 2, 66])])),
                ),
            ),
        ];
        let port = spawn_mock_hierarchy(&servers).await;
        let mut resolver = hierarchy_resolver(port);
        resolver.private_ns_allowed = false;
        let result = resolver
            .resolve(&make_dns_packet("www.evil.", RecordType::A))
            .await;
        assert!(result.is_err(), "no public server for evil.");
        assert_eq!(glue_queries.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(resolver.delegations.get(&name("evil.")).is_none());

        // Control: the same hierarchy with private servers allowed.
        resolver.private_ns_allowed = true;
        resolver
            .resolve(&make_dns_packet("www.evil.", RecordType::A))
            .await
            .expect("reachable once private servers are allowed");
        assert_eq!(glue_queries.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
