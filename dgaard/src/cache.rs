use std::{
    num::NonZeroUsize,
    sync::Mutex,
    time::{Duration, Instant},
};

use lru::LruCache;

use crate::dns::packet::DnsPacket;

/// Longest a negative answer (NXDOMAIN, NODATA) is cached, whatever its SOA
/// says (RFC 2308 §5 recommends a cap; 3 hours is the RFC ceiling).
const MAX_NEGATIVE_TTL: u32 = 3600;

/// DNS record type of OPT (EDNS, RFC 6891): its TTL field carries flags.
const TYPE_OPT: u16 = 41;
/// DNS record type of SOA, the source of negative-caching TTLs.
const TYPE_SOA: u16 = 6;
/// RCODE NXDOMAIN.
const RCODE_NXDOMAIN: u8 = 3;
/// DNS header length; the question starts right after it.
const HEADER_LEN: usize = 12;

/// Query bits that change the answer and so belong in the cache key
/// (RFC 4035 §3.2): DO asks for DNSSEC records, CD disables validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueryFlags {
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
}

impl QueryFlags {
    fn bits(self) -> u8 {
        u8::from(self.dnssec_ok) | (u8::from(self.checking_disabled) << 1)
    }
}

/// What identifies a cached answer: the question (lowercase name, type,
/// class) and the [`QueryFlags`]. Borrowed, so a lookup allocates nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheQuery<'a> {
    pub domain: &'a str,
    pub qtype: u16,
    pub qclass: u16,
    pub flags: QueryFlags,
}

impl<'a> CacheQuery<'a> {
    /// The cache key of a parsed client query (its domain is lowercase).
    pub fn of(packet: &'a DnsPacket) -> Self {
        let message = &packet.message;
        Self {
            domain: &packet.domain,
            qtype: packet.qtype,
            qclass: packet.qclass,
            flags: QueryFlags {
                dnssec_ok: message
                    .edns
                    .as_ref()
                    .is_some_and(|edns| edns.flags().dnssec_ok),
                checking_disabled: message.metadata.checking_disabled,
            },
        }
    }

    fn hash(&self) -> u64 {
        use std::hash::Hasher;

        let mut hasher = twox_hash::XxHash64::with_seed(0);
        hasher.write(self.domain.as_bytes());
        hasher.write_u16(self.qtype);
        hasher.write_u16(self.qclass);
        hasher.write_u8(self.flags.bits());
        hasher.finish()
    }
}

/// How cached record TTLs are adjusted: `[cache] ttl_override` replaces
/// them, `[security.low_ttl] min_ttl_floor_secs` raises low ones. Applied
/// both to the entry lifetime and to the TTLs clients see.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TtlPolicy {
    pub override_secs: u32,
    pub floor_secs: u32,
}

impl TtlPolicy {
    fn adjust(self, ttl: u32) -> u32 {
        if self.override_secs > 0 {
            self.override_secs
        } else {
            ttl.max(self.floor_secs)
        }
    }
}

/// A cached answer ready to send, and how long the entry still lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedAnswer {
    pub bytes: Vec<u8>,
    pub remaining_ttl: u32,
}

struct CacheEntry {
    domain: Box<str>,
    qtype: u16,
    qclass: u16,
    flags: QueryFlags,
    response: Box<[u8]>,
    policy: TtlPolicy,
    /// Seconds the entry lives, from `stored_at` until `expires_at`.
    lifetime: u32,
    stored_at: Instant,
    expires_at: Instant,
}

impl CacheEntry {
    fn matches(&self, query: &CacheQuery<'_>) -> bool {
        self.qtype == query.qtype
            && self.qclass == query.qclass
            && self.flags == query.flags
            && &*self.domain == query.domain
    }
}

/// TTL-aware LRU cache for raw DNS response bytes.
///
/// Entries expire after their TTL elapses and are evicted lazily on the next
/// access. The LRU policy bounds memory when `max_entries` is reached.
///
/// Thread-safe via an internal `Mutex`; the lock is held only during the
/// hash-map operation (no I/O inside the lock).
pub struct ResponseCache {
    inner: Mutex<LruCache<u64, CacheEntry>>,
}

impl ResponseCache {
    pub fn new(max_entries: usize) -> Self {
        let cap = NonZeroUsize::new(max_entries.max(1)).expect("capacity >= 1");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Look up the answer for `query`, as the client of `request` must
    /// receive it: its transaction ID and question case, and every record
    /// TTL counted down by the time the entry has spent in the cache (and
    /// never past the entry's own expiry).
    ///
    /// Returns `None` on a miss or if the entry has expired (removing it).
    pub fn get(&self, query: CacheQuery<'_>, request: &[u8]) -> Option<CachedAnswer> {
        self.get_at(query, request, Instant::now())
    }

    fn get_at(&self, query: CacheQuery<'_>, request: &[u8], now: Instant) -> Option<CachedAnswer> {
        let key = query.hash();
        let (mut bytes, policy, elapsed, remaining_ttl) = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let entry = guard.peek(&key)?;
            if !entry.matches(&query) {
                return None;
            }
            if entry.expires_at <= now {
                guard.pop(&key);
                return None;
            }
            let entry = guard.get(&key)?;
            let elapsed = now.saturating_duration_since(entry.stored_at).as_secs();
            let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);
            let remaining = entry.lifetime.saturating_sub(elapsed);
            (entry.response.to_vec(), entry.policy, elapsed, remaining)
        };

        // No record outlives its entry: a negative answer's SOA TTL may be
        // longer than the negative lifetime (RFC 2308 §5).
        rewrite_ttls(&mut bytes, |ttl| {
            policy
                .adjust(ttl)
                .saturating_sub(elapsed)
                .min(remaining_ttl)
        });
        if bytes.len() >= 2 && request.len() >= 2 {
            bytes[..2].copy_from_slice(&request[..2]);
        }
        copy_question_case(request, &mut bytes);
        Some(CachedAnswer {
            bytes,
            remaining_ttl,
        })
    }

    /// Store `response` for `query`. Its lifetime comes from the response
    /// itself (see [`cache_lifetime`]); responses that must not be cached
    /// (errors, truncated, no usable TTL) are ignored.
    pub fn insert(&self, query: CacheQuery<'_>, response: &[u8], policy: TtlPolicy) {
        let lifetime = cache_lifetime(response, policy);
        if lifetime == 0 {
            return;
        }
        let now = Instant::now();
        let entry = CacheEntry {
            domain: query.domain.into(),
            qtype: query.qtype,
            qclass: query.qclass,
            flags: query.flags,
            response: response.into(),
            policy,
            lifetime,
            stored_at: now,
            expires_at: now + Duration::from_secs(u64::from(lifetime)),
        };
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(query.hash(), entry);
    }

    /// Drop the entry for `query`, if any. Used when a fresh answer for that
    /// name is rejected, so the previous one stops being served.
    pub fn remove(&self, query: CacheQuery<'_>) {
        let key = query.hash();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.peek(&key).is_some_and(|entry| entry.matches(&query)) {
            guard.pop(&key);
        }
    }

    /// Number of entries currently held (including potentially expired ones).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Wipe every cached response. Called on blocklist reload so a
    /// freshly-blocked domain cannot continue to serve its previously
    /// cached "allowed" answer until the TTL expires.
    pub fn clear(&self) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

// ---------------------------------------------------------------------------
// Wire-format helpers (no full parse on the hot path)
// ---------------------------------------------------------------------------

/// One resource record located in a message.
struct RecordRef {
    section: Section,
    rtype: u16,
    ttl_offset: usize,
    rdata: std::ops::Range<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Answer,
    Authority,
    Additional,
}

/// Offset right after the (possibly compressed) name at `pos`.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        match len {
            0 => return Some(pos + 1),
            l if l & 0xC0 == 0xC0 => return (pos + 2 <= msg.len()).then_some(pos + 2),
            l if l & 0xC0 == 0 => pos += 1 + usize::from(l),
            _ => return None,
        }
    }
}

fn read_u16(msg: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]))
}

fn read_u32(msg: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_be_bytes(msg.get(pos..pos + 4)?.try_into().ok()?))
}

/// Every resource record of `msg`, or `None` when malformed.
fn records(msg: &[u8]) -> Option<Vec<RecordRef>> {
    let count = |at: usize| read_u16(msg, at).map(usize::from);
    let (questions, answers, authority, additional) = (count(4)?, count(6)?, count(8)?, count(10)?);
    let mut pos = HEADER_LEN;
    for _ in 0..questions {
        pos = skip_name(msg, pos)? + 4;
    }
    let mut found = Vec::with_capacity(answers + authority + additional);
    let sections = [
        (Section::Answer, answers),
        (Section::Authority, authority),
        (Section::Additional, additional),
    ];
    for (section, n) in sections {
        for _ in 0..n {
            pos = skip_name(msg, pos)?;
            let rtype = read_u16(msg, pos)?;
            let ttl_offset = pos + 4;
            let rdlen = usize::from(read_u16(msg, pos + 8)?);
            let start = pos + 10;
            let end = start.checked_add(rdlen)?;
            if end > msg.len() {
                return None;
            }
            found.push(RecordRef {
                section,
                rtype,
                ttl_offset,
                rdata: start..end,
            });
            pos = end;
        }
    }
    Some(found)
}

/// How long `response` may be cached, after `policy`; 0 when it must not be.
///
/// * a positive answer lives as long as its shortest answer TTL;
/// * a negative answer (NXDOMAIN, or NOERROR without data) lives
///   `min(SOA TTL, SOA MINIMUM)` from the authority section (RFC 2308 §5),
///   capped at [`MAX_NEGATIVE_TTL`]; without a SOA it is not cached;
/// * truncated answers and other RCODEs are not cached.
pub(crate) fn cache_lifetime(response: &[u8], policy: TtlPolicy) -> u32 {
    if response.len() < HEADER_LEN || response[2] & 0x02 != 0 {
        return 0;
    }
    let rcode = response[3] & 0x0F;
    let Some(records) = records(response) else {
        return 0;
    };
    let answer_ttls = || {
        records
            .iter()
            .filter(|r| r.section == Section::Answer)
            .filter_map(|r| read_u32(response, r.ttl_offset))
    };
    match rcode {
        0 if answer_ttls().next().is_some() => answer_ttls()
            .map(|ttl| policy.adjust(ttl))
            .min()
            .unwrap_or(0),
        0 | RCODE_NXDOMAIN => records
            .iter()
            .find(|r| r.section == Section::Authority && r.rtype == TYPE_SOA)
            .and_then(|soa| {
                let ttl = read_u32(response, soa.ttl_offset)?;
                // MINIMUM is the last field of the SOA RDATA.
                let minimum = read_u32(response, soa.rdata.end.checked_sub(4)?)?;
                Some(policy.adjust(ttl.min(minimum)).min(MAX_NEGATIVE_TTL))
            })
            .unwrap_or(0),
        _ => 0,
    }
}

/// Rewrite the TTLs of a fresh `response` as the cache will serve them under
/// `policy`: adjusted, and never past the cache lifetime. The first client
/// then sees the same TTLs as the next ones served from the cache.
pub(crate) fn apply_policy(response: &mut [u8], policy: TtlPolicy) {
    let lifetime = cache_lifetime(response, policy);
    if lifetime == 0 {
        return;
    }
    rewrite_ttls(response, |ttl| policy.adjust(ttl).min(lifetime));
}

/// Rewrite the TTL of every record in `msg` with `f(ttl)`, in place. The
/// OPT pseudo-record is left alone: its TTL field holds EDNS flags.
fn rewrite_ttls(msg: &mut [u8], f: impl Fn(u32) -> u32) {
    let Some(records) = records(msg) else {
        return;
    };
    for record in records.iter().filter(|r| r.rtype != TYPE_OPT) {
        if let Some(ttl) = read_u32(msg, record.ttl_offset) {
            msg[record.ttl_offset..record.ttl_offset + 4].copy_from_slice(&f(ttl).to_be_bytes());
        }
    }
}

/// Copy the QNAME of `request` onto the question of `response` when they
/// name the same domain, so the client sees the case it asked with
/// (stubs may compare it; DNS 0x20 randomization must not leak).
pub(crate) fn copy_question_case(request: &[u8], response: &mut [u8]) {
    let has_question = |msg: &[u8]| read_u16(msg, 4).is_some_and(|count| count > 0);
    if !has_question(request) || !has_question(response) {
        return;
    }
    let (Some(req_end), Some(resp_end)) = (
        skip_name(request, HEADER_LEN),
        skip_name(response, HEADER_LEN),
    ) else {
        return;
    };
    if req_end != resp_end {
        return;
    }
    let (req_name, resp_name) = (
        &request[HEADER_LEN..req_end],
        &response[HEADER_LEN..resp_end],
    );
    // Compression pointers never appear in a first question; both must be
    // plain labels for a byte-wise case copy to be meaningful.
    if req_name.eq_ignore_ascii_case(resp_name) && !req_name.iter().any(|&b| b & 0xC0 == 0xC0) {
        response[HEADER_LEN..resp_end].copy_from_slice(req_name);
    }
}

#[cfg(test)]
mod tests {
    use hickory_resolver::proto::op::{Edns, Message, MessageType, Query, ResponseCode};
    use hickory_resolver::proto::rr::rdata::{A, CNAME, SOA};
    use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};

    use super::*;

    const QTYPE_A: u16 = 1;
    const CLASS_IN: u16 = 1;

    fn key(domain: &str) -> CacheQuery<'_> {
        CacheQuery {
            domain,
            qtype: QTYPE_A,
            qclass: CLASS_IN,
            flags: QueryFlags::default(),
        }
    }

    fn name(domain: &str) -> Name {
        Name::from_ascii(format!("{domain}.")).unwrap()
    }

    fn query_message(domain: &str, id: u16) -> Message {
        let mut msg = Message::query();
        msg.metadata.id = id;
        msg.add_query(Query::query(name(domain), RecordType::A));
        msg
    }

    fn packet(bytes: &[u8]) -> DnsPacket {
        match DnsPacket::screen(bytes) {
            crate::dns::packet::Incoming::Query(packet) => packet,
            _ => panic!("not a query"),
        }
    }

    fn request(domain: &str, id: u16) -> Vec<u8> {
        query_message(domain, id).to_vec().unwrap()
    }

    fn response(domain: &str, rcode: ResponseCode) -> Message {
        let mut msg = query_message(domain, 0x1111);
        msg.metadata.message_type = MessageType::Response;
        msg.metadata.response_code = rcode;
        msg
    }

    fn a_record(domain: &str, ttl: u32) -> Record {
        Record::from_rdata(name(domain), ttl, RData::A(A::new(93, 184, 216, 34)))
    }

    fn soa_record(zone: &str, ttl: u32, minimum: u32) -> Record {
        let soa = SOA::new(
            name(&format!("ns.{zone}")),
            name(&format!("admin.{zone}")),
            1,
            7200,
            900,
            1_209_600,
            minimum,
        );
        Record::from_rdata(name(zone), ttl, RData::SOA(soa))
    }

    fn positive(domain: &str, ttl: u32) -> Vec<u8> {
        let mut msg = response(domain, ResponseCode::NoError);
        msg.add_answer(a_record(domain, ttl));
        msg.to_vec().unwrap()
    }

    fn negative(domain: &str, rcode: ResponseCode, soa_ttl: u32, minimum: u32) -> Vec<u8> {
        let mut msg = response(domain, rcode);
        msg.add_authority(soa_record("example.com", soa_ttl, minimum));
        msg.to_vec().unwrap()
    }

    fn ttls(bytes: &[u8]) -> Vec<u32> {
        let msg = Message::from_vec(bytes).unwrap();
        msg.answers
            .iter()
            .chain(&msg.authorities)
            .chain(&msg.additionals)
            .map(|record| record.ttl)
            .collect()
    }

    // ---- key ----

    #[test]
    fn hit_returns_the_stored_answer() {
        let cache = ResponseCache::new(16);
        cache.insert(
            key("example.com"),
            &positive("example.com", 300),
            TtlPolicy::default(),
        );
        let hit = cache
            .get(key("example.com"), &request("example.com", 7))
            .unwrap();
        assert_eq!(ttls(&hit.bytes), [300]);
        assert_eq!(hit.remaining_ttl, 300);
    }

    #[test]
    fn the_key_covers_type_class_and_dnssec_bits() {
        let cache = ResponseCache::new(16);
        cache.insert(
            key("example.com"),
            &positive("example.com", 300),
            TtlPolicy::default(),
        );
        let req = request("example.com", 7);
        let others = [
            CacheQuery {
                qtype: 28,
                ..key("example.com")
            },
            CacheQuery {
                qclass: 3,
                ..key("example.com")
            },
            CacheQuery {
                flags: QueryFlags {
                    dnssec_ok: true,
                    checking_disabled: false,
                },
                ..key("example.com")
            },
            CacheQuery {
                flags: QueryFlags {
                    dnssec_ok: false,
                    checking_disabled: true,
                },
                ..key("example.com")
            },
            key("other.com"),
        ];
        for other in others {
            assert!(cache.get(other, &req).is_none(), "{other:?} must miss");
        }
        assert!(cache.get(key("example.com"), &req).is_some());
    }

    #[test]
    fn dnssec_and_plain_answers_are_kept_apart() {
        let cache = ResponseCache::new(16);
        let with_do = CacheQuery {
            flags: QueryFlags {
                dnssec_ok: true,
                checking_disabled: false,
            },
            ..key("example.com")
        };
        cache.insert(with_do, &positive("example.com", 300), TtlPolicy::default());
        cache.insert(
            key("example.com"),
            &positive("example.com", 60),
            TtlPolicy::default(),
        );
        let req = request("example.com", 7);
        assert_eq!(ttls(&cache.get(with_do, &req).unwrap().bytes), [300]);
        assert_eq!(
            ttls(&cache.get(key("example.com"), &req).unwrap().bytes),
            [60]
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn key_of_a_packet_reads_do_and_cd() {
        let mut msg = query_message("Example.COM", 1);
        msg.metadata.checking_disabled = true;
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        msg.set_edns(edns);
        let parsed = packet(&msg.to_vec().unwrap());
        let query = CacheQuery::of(&parsed);
        assert_eq!(query.domain, "example.com");
        assert_eq!((query.qtype, query.qclass), (QTYPE_A, CLASS_IN));
        assert_eq!(
            query.flags,
            QueryFlags {
                dnssec_ok: true,
                checking_disabled: true
            }
        );

        let plain = packet(&request("example.com", 1));
        assert_eq!(CacheQuery::of(&plain).flags, QueryFlags::default());
    }

    // ---- served bytes ----

    #[test]
    fn hit_carries_the_client_txid_and_question_case() {
        let cache = ResponseCache::new(16);
        cache.insert(
            key("example.com"),
            &positive("example.com", 300),
            TtlPolicy::default(),
        );
        let hit = cache
            .get(key("example.com"), &request("ExAmPlE.CoM", 0xBEEF))
            .unwrap();
        let msg = Message::from_vec(&hit.bytes).unwrap();
        assert_eq!(msg.metadata.id, 0xBEEF);
        assert_eq!(msg.queries[0].name().to_ascii(), "ExAmPlE.CoM.");
    }

    #[test]
    fn ttls_count_down_while_cached() {
        let cache = ResponseCache::new(16);
        let mut msg = response("example.com", ResponseCode::NoError);
        msg.add_answer(a_record("example.com", 300));
        msg.add_additional(a_record("ns.example.com", 600));
        cache.insert(
            key("example.com"),
            &msg.to_vec().unwrap(),
            TtlPolicy::default(),
        );

        let later = Instant::now() + Duration::from_secs(100);
        let hit = cache
            .get_at(key("example.com"), &request("example.com", 1), later)
            .unwrap();
        // The additional record is capped at the entry's remaining life.
        assert_eq!(ttls(&hit.bytes), [200, 200]);
        assert_eq!(hit.remaining_ttl, 200);
    }

    #[test]
    fn expired_entries_miss_and_are_dropped() {
        let cache = ResponseCache::new(16);
        cache.insert(
            key("example.com"),
            &positive("example.com", 30),
            TtlPolicy::default(),
        );
        let later = Instant::now() + Duration::from_secs(31);
        assert!(
            cache
                .get_at(key("example.com"), &request("example.com", 1), later)
                .is_none()
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn opt_record_flags_survive_the_ttl_rewrite() {
        let cache = ResponseCache::new(16);
        let mut msg = response("example.com", ResponseCode::NoError);
        msg.add_answer(a_record("example.com", 300));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        msg.set_edns(edns);
        cache.insert(
            key("example.com"),
            &msg.to_vec().unwrap(),
            TtlPolicy::default(),
        );

        let later = Instant::now() + Duration::from_secs(100);
        let hit = cache
            .get_at(key("example.com"), &request("example.com", 1), later)
            .unwrap();
        let served = Message::from_vec(&hit.bytes).unwrap();
        assert!(served.edns.unwrap().flags().dnssec_ok);
        assert_eq!(served.answers[0].ttl, 200);
    }

    // ---- TTL policy ----

    #[test]
    fn ttl_override_is_served_and_sets_the_lifetime() {
        let cache = ResponseCache::new(16);
        let policy = TtlPolicy {
            override_secs: 60,
            floor_secs: 0,
        };
        cache.insert(key("example.com"), &positive("example.com", 3600), policy);
        let req = request("example.com", 1);
        assert_eq!(
            ttls(&cache.get(key("example.com"), &req).unwrap().bytes),
            [60]
        );
        let later = Instant::now() + Duration::from_secs(61);
        assert!(cache.get_at(key("example.com"), &req, later).is_none());
    }

    #[test]
    fn ttl_floor_raises_low_ttls() {
        let cache = ResponseCache::new(16);
        let policy = TtlPolicy {
            override_secs: 0,
            floor_secs: 30,
        };
        cache.insert(key("example.com"), &positive("example.com", 5), policy);
        let req = request("example.com", 1);
        assert_eq!(
            ttls(&cache.get(key("example.com"), &req).unwrap().bytes),
            [30]
        );
        let later = Instant::now() + Duration::from_secs(10);
        let hit = cache.get_at(key("example.com"), &req, later).unwrap();
        assert_eq!(ttls(&hit.bytes), [20]);
    }

    #[test]
    fn fresh_answers_get_the_ttls_the_cache_will_serve() {
        let mut bytes = positive("example.com", 3600);
        apply_policy(
            &mut bytes,
            TtlPolicy {
                override_secs: 60,
                floor_secs: 0,
            },
        );
        assert_eq!(ttls(&bytes), [60]);

        let mut bytes = positive("example.com", 5);
        apply_policy(
            &mut bytes,
            TtlPolicy {
                override_secs: 0,
                floor_secs: 30,
            },
        );
        assert_eq!(ttls(&bytes), [30]);

        let mut bytes = negative("nope.example.com", ResponseCode::NXDomain, 900, 60);
        apply_policy(&mut bytes, TtlPolicy::default());
        assert_eq!(ttls(&bytes), [60], "SOA TTL capped at the negative TTL");

        // Uncacheable answers are left untouched.
        let mut bytes = negative("example.com", ResponseCode::ServFail, 900, 60);
        let original = bytes.clone();
        apply_policy(
            &mut bytes,
            TtlPolicy {
                override_secs: 60,
                floor_secs: 0,
            },
        );
        assert_eq!(bytes, original);
    }

    #[test]
    fn zero_ttl_answers_are_not_cached() {
        let cache = ResponseCache::new(16);
        cache.insert(
            key("example.com"),
            &positive("example.com", 0),
            TtlPolicy::default(),
        );
        assert_eq!(cache.len(), 0);
    }

    // ---- what gets cached, and for how long ----

    #[test]
    fn positive_lifetime_is_the_shortest_answer_ttl() {
        let mut msg = response("www.example.com", ResponseCode::NoError);
        msg.add_answer(Record::from_rdata(
            name("www.example.com"),
            3600,
            RData::CNAME(CNAME(name("example.com"))),
        ));
        msg.add_answer(a_record("example.com", 120));
        assert_eq!(
            cache_lifetime(&msg.to_vec().unwrap(), TtlPolicy::default()),
            120
        );
    }

    #[test]
    fn nxdomain_is_cached_for_the_soa_negative_ttl() {
        // RFC 2308 §5: min(SOA TTL, SOA MINIMUM).
        let bytes = negative("nope.example.com", ResponseCode::NXDomain, 900, 60);
        assert_eq!(cache_lifetime(&bytes, TtlPolicy::default()), 60);
        let bytes = negative("nope.example.com", ResponseCode::NXDomain, 45, 600);
        assert_eq!(cache_lifetime(&bytes, TtlPolicy::default()), 45);

        let cache = ResponseCache::new(16);
        let bytes = negative("nope.example.com", ResponseCode::NXDomain, 900, 60);
        cache.insert(key("nope.example.com"), &bytes, TtlPolicy::default());
        let hit = cache
            .get(key("nope.example.com"), &request("nope.example.com", 9))
            .unwrap();
        let served = Message::from_vec(&hit.bytes).unwrap();
        assert_eq!(served.metadata.response_code, ResponseCode::NXDomain);
        // The SOA never outlives the negative entry.
        assert!(served.authorities[0].ttl <= 60);
    }

    #[test]
    fn nodata_is_cached_like_nxdomain() {
        let bytes = negative("example.com", ResponseCode::NoError, 300, 120);
        assert_eq!(cache_lifetime(&bytes, TtlPolicy::default()), 120);
    }

    #[test]
    fn negative_lifetime_is_capped() {
        let bytes = negative("nope.example.com", ResponseCode::NXDomain, 86_400, 86_400);
        assert_eq!(
            cache_lifetime(&bytes, TtlPolicy::default()),
            MAX_NEGATIVE_TTL
        );
        let policy = TtlPolicy {
            override_secs: 7200,
            floor_secs: 0,
        };
        assert_eq!(cache_lifetime(&bytes, policy), MAX_NEGATIVE_TTL);
    }

    #[test]
    fn negative_answers_without_soa_are_not_cached() {
        let bytes = response("nope.example.com", ResponseCode::NXDomain)
            .to_vec()
            .unwrap();
        assert_eq!(cache_lifetime(&bytes, TtlPolicy::default()), 0);
        let bytes = response("example.com", ResponseCode::NoError)
            .to_vec()
            .unwrap();
        assert_eq!(cache_lifetime(&bytes, TtlPolicy::default()), 0);
    }

    #[test]
    fn errors_truncated_and_malformed_answers_are_not_cached() {
        let servfail = negative("example.com", ResponseCode::ServFail, 300, 300);
        assert_eq!(cache_lifetime(&servfail, TtlPolicy::default()), 0);

        let mut truncated = response("example.com", ResponseCode::NoError);
        truncated.metadata.truncation = true;
        truncated.add_answer(a_record("example.com", 300));
        assert_eq!(
            cache_lifetime(&truncated.to_vec().unwrap(), TtlPolicy::default()),
            0
        );

        let mut cut = positive("example.com", 300);
        cut.truncate(cut.len() - 2);
        assert_eq!(cache_lifetime(&cut, TtlPolicy::default()), 0);
        assert_eq!(cache_lifetime(&[0u8; 5], TtlPolicy::default()), 0);
    }

    // ---- maintenance ----

    #[test]
    fn remove_drops_only_the_matching_entry() {
        let cache = ResponseCache::new(16);
        let with_do = CacheQuery {
            flags: QueryFlags {
                dnssec_ok: true,
                checking_disabled: false,
            },
            ..key("example.com")
        };
        cache.insert(
            key("example.com"),
            &positive("example.com", 300),
            TtlPolicy::default(),
        );
        cache.insert(with_do, &positive("example.com", 300), TtlPolicy::default());
        cache.remove(with_do);
        let req = request("example.com", 1);
        assert!(cache.get(with_do, &req).is_none());
        assert!(cache.get(key("example.com"), &req).is_some());
    }

    #[test]
    fn lru_bound_and_clear() {
        let cache = ResponseCache::new(2);
        for domain in ["a.com", "b.com", "c.com"] {
            cache.insert(key(domain), &positive(domain, 300), TtlPolicy::default());
        }
        assert_eq!(cache.len(), 2);
        assert!(cache.get(key("a.com"), &request("a.com", 1)).is_none());
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    // ---- question case ----

    #[test]
    fn question_case_is_copied_only_for_the_same_name() {
        let mut bytes = positive("example.com", 300);
        let original = bytes.clone();
        copy_question_case(&request("other.com", 1), &mut bytes);
        assert_eq!(bytes, original, "a different name is left alone");
        copy_question_case(&request("exbmple.com", 1), &mut bytes);
        assert_eq!(bytes, original, "same length, different name");

        copy_question_case(&request("EXAMPLE.com", 1), &mut bytes);
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.queries[0].name().to_ascii(), "EXAMPLE.com.");
    }

    #[test]
    fn question_case_needs_a_question_on_both_sides() {
        let mut no_question = response("example.com", ResponseCode::NoError);
        no_question.queries.clear();
        no_question.add_answer(a_record("example.com", 300));
        let mut bytes = no_question.to_vec().unwrap();
        let original = bytes.clone();
        copy_question_case(&request("EXAMPLE.COM", 1), &mut bytes);
        assert_eq!(bytes, original);

        let mut empty_request = query_message("example.com", 1);
        empty_request.queries.clear();
        let mut bytes = positive("example.com", 300);
        let original = bytes.clone();
        copy_question_case(&empty_request.to_vec().unwrap(), &mut bytes);
        assert_eq!(bytes, original);
    }

    #[test]
    fn class_of_a_query_is_part_of_its_wire_question() {
        // Sanity check for the class-keyed tests: a CHAOS query differs.
        let mut msg = Message::query();
        let mut question = Query::query(name("example.com"), RecordType::A);
        question.set_query_class(DNSClass::CH);
        msg.add_query(question);
        let packet = packet(&msg.to_vec().unwrap());
        assert_eq!(CacheQuery::of(&packet).qclass, 3);
    }
}
