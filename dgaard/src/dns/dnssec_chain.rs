//! Recursive-mode DNSSEC chain of trust.
//!
//! This module owns the building blocks the iterative resolver uses to
//! validate answers against a chain of trust rooted at the IANA root KSKs:
//!
//! * compiled-in **trust anchors** ([`ROOT_TRUST_ANCHORS`]: KSK-2017 and
//!   KSK-2024) that authenticate the root DNSKEY rrset;
//! * a bounded, TTL-driven **per-zone trust cache** filled by the resolver
//!   as it walks the delegation chain;
//! * a **verifier** wrapping hickory's crypto-only `Verifier` with the
//!   RFC 4035 §5.3.1 checks it leaves to the caller (validity window,
//!   signer name, zone-key flag);
//! * the **trust hand-off** parent → child through verified DS records,
//!   or a verified NSEC/NSEC3 proof that the child has no DS.
//!
//! ## Building the chain
//!
//! [`crate::dns::recursive::RecursiveResolver`] fetches the root DNSKEY
//! rrset and validates it against the anchors, then at every referral
//! stores the child's DS once verified under the parent's keys (never
//! before) and fetches the child's DNSKEY rrset, or records an insecure
//! delegation when the parent proves the DS absent (NSEC, NSEC3, NSEC3
//! opt-out). Zone cuts hosted on the parent's servers, which answer
//! without a referral, are chained from the final response: RRSIG
//! signers below the answering zone get their DS and DNSKEY fetched, and
//! unsigned data under a signed zone triggers a search for an insecure
//! cut.
//!
//! ## Validating answers (fail-closed)
//!
//! [`RecursiveDnssecValidator::validate_message_for`] checks every answer
//! rrset against its closest known zone:
//!
//! * proven insecure zone, or no chain known at all → `Insecure`;
//! * signed zone → the rrset needs an RRSIG from **that** zone, inside its
//!   validity window, verifying under one of the zone's keys, else
//!   `Bogus` — stripped, forged, expired or foreign signatures all land
//!   here;
//! * verified DS without a validated DNSKEY (broken chain) → `Bogus`.
//!
//! NXDOMAIN and NODATA answers, also at the end of a CNAME chain, need a
//! verified NSEC/NSEC3 denial when the zone is signed.
//!
//! Deliberate gaps: wildcard-expansion proofs (RFC 4035 §5.3.4), NSEC
//! wildcard denial and the NSEC3 closest-encloser proof (RFC 5155 §8) are
//! not required; an opt-out NSEC3 covering the child (or an ancestor below
//! the parent) is accepted as proof of an unsigned delegation.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use hickory_resolver::proto::dnssec::rdata::DNSSECRData;
// Re-export so callers (e.g. the iterative resolver's tests) can
// construct trust-anchor DS records without a second hickory import.
pub use hickory_resolver::proto::dnssec::rdata::DS;
use hickory_resolver::proto::dnssec::rdata::{DNSKEY, NSEC, NSEC3, RRSIG};
use hickory_resolver::proto::dnssec::{Algorithm, DigestType, Nsec3HashAlgorithm, Verifier};
use hickory_resolver::proto::op::{Message, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType, SerialNumber};

/// Outcome of validating a resource-record set (or a whole response)
/// against the in-memory trust state.
///
/// `Secure` and `Bogus` are the cryptographically definitive outcomes.
/// `Insecure` means the data sits under a zone with no chain of trust
/// (unsigned zone, insecure delegation proven by the parent, or no
/// chain known at all), so the higher layer passes it through.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DnssecVerdict {
    /// Signature verified back to the root trust anchor.
    Secure,
    /// No chain of trust applies to this data.
    Insecure,
    /// The data sits under a zone known to be signed and could not be
    /// verified: missing or bad signature, expired or not-yet-valid
    /// signature, wrong signer, unknown key, broken chain, …
    Bogus,
}

// ---------------------------------------------------------------------------
// IANA root trust anchors
// ---------------------------------------------------------------------------

/// Trust anchor pinned at compile time. The recursive validator
/// pre-loads the root zone's DS rrset from these, so every chain it
/// later constructs from upstream-fetched DNSKEYs terminates at IANA.
///
/// Rolling these requires a coordinated release because long-lived
/// router images may not see the update for years. See
/// [`https://www.iana.org/dnssec/files`].
#[derive(Debug, Clone, Copy)]
pub struct RootTrustAnchor {
    pub key_tag: u16,
    pub algorithm: Algorithm,
    pub digest_type: DigestType,
    /// Hex-decoded digest bytes.
    pub digest: &'static [u8],
}

/// IANA root-zone KSK in production since 2017 ("KSK-2017"), from
/// `https://data.iana.org/root-anchors/root-anchors.xml`.
pub const ROOT_KSK_2017: RootTrustAnchor = RootTrustAnchor {
    key_tag: 20326,
    algorithm: Algorithm::RSASHA256,
    digest_type: DigestType::SHA256,
    digest: &hex32([
        0xe0, 0x6d, 0x44, 0xb8, 0x0b, 0x8f, 0x1d, 0x39, 0xa9, 0x5c, 0x0b, 0x0d, 0x7c, 0x65, 0xd0,
        0x84, 0x58, 0xe8, 0x80, 0x40, 0x9b, 0xbc, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xc7, 0xf8,
        0xec, 0x8d,
    ]),
};

/// IANA root-zone KSK published in 2024 ("KSK-2024"), from
/// `https://data.iana.org/root-anchors/root-anchors.xml` (validFrom
/// 2024-07-18). Since the October 2026 rollover it is the key that signs
/// the root DNSKEY rrset; the `ksk_*_digest_matches_iana_public_key`
/// tests recompute both digests from the published public keys.
pub const ROOT_KSK_2024: RootTrustAnchor = RootTrustAnchor {
    key_tag: 38696,
    algorithm: Algorithm::RSASHA256,
    digest_type: DigestType::SHA256,
    digest: &hex32([
        0x68, 0x3d, 0x2d, 0x0a, 0xcb, 0x8c, 0x9b, 0x71, 0x2a, 0x19, 0x48, 0xb2, 0x7f, 0x74, 0x12,
        0x19, 0x29, 0x8d, 0x0a, 0x45, 0x0d, 0x61, 0x2c, 0x48, 0x3a, 0xf4, 0x44, 0xa4, 0xc0, 0xfb,
        0x2b, 0x16,
    ]),
};

/// Every root KSK the validator trusts. Both are kept across the
/// rollover window so either signature over the root DNSKEY validates.
pub const ROOT_TRUST_ANCHORS: &[RootTrustAnchor] = &[ROOT_KSK_2017, ROOT_KSK_2024];

const fn hex32(bytes: [u8; 32]) -> [u8; 32] {
    bytes
}

/// Upper bound on how long a DS, DNSKEY or insecure-delegation fact is
/// trusted, whatever TTL the zone advertises.
pub const MAX_TRUST_TTL: Duration = Duration::from_secs(86_400);

/// Upper bound on the number of zones in the trust cache. A hostile zone
/// delegating thousands of signed sub-zones cannot grow memory past it.
pub const MAX_CACHED_ZONES: usize = 4096;

/// Current time as an RRSIG timestamp (RFC 4034 §3.1.5: seconds since
/// the epoch modulo 2^32, compared with serial-number arithmetic).
fn unix_now() -> SerialNumber {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    SerialNumber::new(secs as u32)
}

// ---------------------------------------------------------------------------
// Per-zone state cached by the validator
// ---------------------------------------------------------------------------

/// Per-zone state kept by the validator. Every field is authenticated
/// before it is stored: DS records verified under the parent's keys (or
/// the compiled-in anchors for the root), DNSKEYs verified under one of
/// those DS, and `insecure` only after a signed NSEC/NSEC3 proof.
#[derive(Debug, Default, Clone)]
pub struct ZoneTrustState {
    /// DS records in the parent zone that point to **this** zone's KSK.
    /// Pre-seeded for the root zone from [`ROOT_TRUST_ANCHORS`].
    pub ds_in_parent: Vec<DS>,
    /// DNSKEYs published at the zone apex, verified against `ds_in_parent`.
    pub dnskeys: Vec<DNSKEY>,
    /// The parent proved that this delegation has no DS: the zone is
    /// legitimately unsigned and data below it is `Insecure`.
    pub insecure: bool,
    /// Deadline for `ds_in_parent` and `insecure`; `None` never expires
    /// (trust anchors).
    pub ds_expires_at: Option<Instant>,
    /// Deadline for `dnskeys`; `None` never expires.
    pub keys_expires_at: Option<Instant>,
}

impl ZoneTrustState {
    /// Drop every component whose deadline has passed.
    fn expire(&mut self, now: Instant) {
        if self.ds_expires_at.is_some_and(|deadline| deadline <= now) {
            self.ds_in_parent.clear();
            self.insecure = false;
            self.ds_expires_at = None;
        }
        if self.keys_expires_at.is_some_and(|deadline| deadline <= now) {
            self.dnskeys.clear();
            self.keys_expires_at = None;
        }
    }

    fn is_empty(&self) -> bool {
        self.ds_in_parent.is_empty() && self.dnskeys.is_empty() && !self.insecure
    }

    /// What this zone says about the data below it, if anything.
    fn status(&self) -> Option<ZoneStatus> {
        if self.insecure {
            Some(ZoneStatus::Insecure)
        } else if !self.dnskeys.is_empty() {
            Some(ZoneStatus::Secure(self.dnskeys.clone()))
        } else if !self.ds_in_parent.is_empty() {
            Some(ZoneStatus::Broken)
        } else {
            None
        }
    }
}

/// Trust status of one zone, derived from its cached state.
#[derive(Debug, Clone)]
pub enum ZoneStatus {
    /// Validated DNSKEYs: data below must be signed by them.
    Secure(Vec<DNSKEY>),
    /// Proven insecure delegation: data below is unsigned by design.
    Insecure,
    /// A verified DS exists but no DNSKEY could be validated against it:
    /// the zone is signed and nothing below can be verified.
    Broken,
}

/// Name whose closest enclosing zone signs an rrset of `rtype` at
/// `owner`. A DS rrset lives in the parent side of the zone cut.
fn signing_lookup_name(owner: &Name, rtype: RecordType) -> Name {
    if rtype == RecordType::DS && !owner.is_root() {
        owner.base_name()
    } else {
        owner.clone()
    }
}

/// RFC 4035 §5.3.1 checks that hickory's crypto-only verifier leaves to
/// the caller: the signer is the expected zone and encloses the owner,
/// and `now` sits inside the signature's validity window.
fn rrsig_context_ok(rrsig: &RRSIG, owner: &Name, zone: &Name, now: SerialNumber) -> bool {
    let input = rrsig.input();
    input.signer_name == *zone
        && zone.zone_of(owner)
        && input.sig_inception <= now
        && now <= input.sig_expiration
}

/// Return the first RRSIG in `rrsigs` that passes the context checks and
/// verifies `records` under one of `keys` (matching key tag and
/// algorithm, zone-key flag set, not revoked).
fn verify_with_keys<'a>(
    keys: &[DNSKEY],
    zone: &Name,
    owner: &Name,
    dns_class: DNSClass,
    rrsigs: &[&'a RRSIG],
    records: &[Record],
    now: SerialNumber,
) -> Option<&'a RRSIG> {
    rrsigs.iter().copied().find(|rrsig| {
        let input = rrsig.input();
        rrsig_context_ok(rrsig, owner, zone, now)
            && keys
                .iter()
                .filter(|key| {
                    key.zone_key()
                        && !key.revoke()
                        && key.algorithm() == input.algorithm
                        && key
                            .calculate_key_tag()
                            .is_ok_and(|tag| tag == input.key_tag)
                })
                .any(|key| {
                    key.verify_rrsig(owner, dns_class, rrsig, records.iter())
                        .is_ok()
                })
    })
}

/// How long a verified rrset may be trusted: its smallest TTL, capped by
/// the RRSIG's original TTL, the time left before the signature expires
/// and [`MAX_TRUST_TTL`].
fn trust_deadline(records: &[Record], rrsig: &RRSIG, now: SerialNumber) -> Instant {
    let input = rrsig.input();
    let record_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(0);
    // `now <= sig_expiration` was checked: the wrapping distance is the
    // remaining validity in seconds.
    let until_expiry = input.sig_expiration.get().wrapping_sub(now.get());
    let ttl = record_ttl.min(input.original_ttl).min(until_expiry);
    Instant::now() + Duration::from_secs(u64::from(ttl)).min(MAX_TRUST_TTL)
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

/// Process-wide DNSSEC chain-of-trust state. Cheap to clone — internal
/// storage is an `Arc<DashMap<Name, ZoneTrustState>>`, so one instance
/// can be shared across the resolver and worker tasks.
#[derive(Debug, Clone)]
pub struct RecursiveDnssecValidator {
    zones: Arc<DashMap<Name, ZoneTrustState>>,
    /// Root DS rrset from the compiled-in anchors, restored by [`Self::clear`].
    anchors: Arc<[DS]>,
    /// Cache bound, [`MAX_CACHED_ZONES`] outside tests.
    max_zones: usize,
}

impl Default for RecursiveDnssecValidator {
    fn default() -> Self {
        Self::with_root_anchors(ROOT_TRUST_ANCHORS)
    }
}

impl RecursiveDnssecValidator {
    /// Construct a validator seeded with `anchors` as the *parent DS* of
    /// the root zone. Walks then fill in DNSKEYs as the resolver
    /// discovers and verifies them.
    pub fn with_root_anchors(anchors: &[RootTrustAnchor]) -> Self {
        let anchors: Arc<[DS]> = anchors
            .iter()
            .map(|anchor| {
                DS::new(
                    anchor.key_tag,
                    anchor.algorithm,
                    anchor.digest_type,
                    anchor.digest.to_vec(),
                )
            })
            .collect();
        let validator = Self {
            zones: Arc::new(DashMap::new()),
            anchors,
            max_zones: MAX_CACHED_ZONES,
        };
        validator.seed_anchors();
        validator
    }

    /// Construct with no anchor (useful in tests that exercise the
    /// validator in isolation). Real deployments must use
    /// [`Self::with_root_anchors`] or [`Self::default`].
    #[cfg(test)]
    pub fn empty() -> Self {
        Self {
            zones: Arc::new(DashMap::new()),
            anchors: Arc::from(Vec::new()),
            max_zones: MAX_CACHED_ZONES,
        }
    }

    /// Test seam: a validator whose cache holds at most `max_zones`.
    #[cfg(test)]
    pub fn with_max_zones_for_test(mut self, max_zones: usize) -> Self {
        self.max_zones = max_zones;
        self
    }

    fn seed_anchors(&self) {
        if self.anchors.is_empty() {
            return;
        }
        self.zones.insert(
            Name::root(),
            ZoneTrustState {
                ds_in_parent: self.anchors.to_vec(),
                ..ZoneTrustState::default()
            },
        );
    }

    /// Live (non-expired) state of exactly `zone`. The state is cloned
    /// out so no shard lock is held by the caller during crypto.
    pub fn zone(&self, zone: &Name) -> Option<ZoneTrustState> {
        let now = Instant::now();
        let mut state = self.zones.get(zone)?.clone();
        state.expire(now);
        if state.is_empty() {
            self.zones
                .remove_if(zone, |_, stored| stored.is_expired_at(now));
            return None;
        }
        Some(state)
    }

    /// Trust status of exactly `zone`, if the cache knows it.
    pub fn zone_status(&self, zone: &Name) -> Option<ZoneStatus> {
        self.zone(zone).and_then(|state| state.status())
    }

    /// True when `zone` has a verified DS but no validated DNSKEY yet:
    /// the resolver should fetch the zone's DNSKEY rrset.
    pub fn needs_keys(&self, zone: &Name) -> bool {
        matches!(self.zone_status(zone), Some(ZoneStatus::Broken))
    }

    /// The deepest zone enclosing `name` (itself included) whose status
    /// the cache knows, with that status.
    pub fn closest_zone(&self, name: &Name) -> Option<(Name, ZoneStatus)> {
        let mut candidate = name.clone();
        loop {
            if let Some(status) = self.zone_status(&candidate) {
                return Some((candidate, status));
            }
            if candidate.is_root() {
                return None;
            }
            candidate = candidate.base_name();
        }
    }

    /// Test-only seam: insert a zone's trust state without going
    /// through the verification primitives.
    #[cfg(test)]
    pub fn seed_zone_for_test(&self, zone: Name, state: ZoneTrustState) {
        self.zones.insert(zone, state);
    }

    /// Drop every learned zone and keep only the compiled-in root
    /// anchors, so the validator never falls back to "no chain at all".
    pub fn clear(&self) {
        self.zones.clear();
        self.seed_anchors();
    }

    /// Insert or update `zone`, keeping the cache within `max_zones`.
    fn update_zone(&self, zone: &Name, update: impl FnOnce(&mut ZoneTrustState)) {
        if !self.zones.contains_key(zone) && self.zones.len() >= self.max_zones {
            self.make_room();
        }
        let mut entry = self.zones.entry(zone.clone()).or_default();
        update(&mut entry);
    }

    /// Free at least one slot: drop expired zones first, then evict an
    /// arbitrary zone other than the root (which holds the anchors).
    fn make_room(&self) {
        let now = Instant::now();
        self.zones
            .retain(|name, state| name.is_root() || !state.is_expired_at(now));
        if self.zones.len() < self.max_zones {
            return;
        }
        let victim = self
            .zones
            .iter()
            .find(|entry| !entry.key().is_root())
            .map(|entry| entry.key().clone());
        if let Some(victim) = victim {
            self.zones.remove(&victim);
        }
    }

    /// Record a DS rrset published by `parent_zone` for `child_zone`.
    ///
    /// The DS is stored only when one of `rrsigs` verifies it under the
    /// parent's validated DNSKEYs. Returns:
    /// * `Secure` — DS verified and stored;
    /// * `Bogus` — the parent is signed but the DS rrset does not verify
    ///   (nothing stored: data below the child then fails validation);
    /// * `Insecure` — the parent has no validated keys; nothing stored.
    pub fn record_ds_for_child(
        &self,
        parent_zone: &Name,
        child_zone: &Name,
        records: &[Record],
        rrsigs: &[RRSIG],
    ) -> DnssecVerdict {
        self.record_ds_for_child_at(parent_zone, child_zone, records, rrsigs, unix_now())
    }

    fn record_ds_for_child_at(
        &self,
        parent_zone: &Name,
        child_zone: &Name,
        records: &[Record],
        rrsigs: &[RRSIG],
        now: SerialNumber,
    ) -> DnssecVerdict {
        let Some(ZoneStatus::Secure(parent_keys)) = self.zone_status(parent_zone) else {
            return DnssecVerdict::Insecure;
        };
        let ds_values: Vec<DS> = records
            .iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::DS(ds)) if r.name == *child_zone => Some(ds.clone()),
                _ => None,
            })
            .collect();
        if ds_values.is_empty() || !parent_zone.zone_of(child_zone) || parent_zone == child_zone {
            return DnssecVerdict::Bogus;
        }
        let sig_refs: Vec<&RRSIG> = rrsigs.iter().collect();
        let Some(rrsig) = verify_with_keys(
            &parent_keys,
            parent_zone,
            child_zone,
            DNSClass::IN,
            &sig_refs,
            records,
            now,
        ) else {
            return DnssecVerdict::Bogus;
        };
        let deadline = trust_deadline(records, rrsig, now);
        self.update_zone(child_zone, |state| {
            if state.ds_in_parent != ds_values {
                // New DS set: keys validated against the old one must be
                // validated again.
                state.dnskeys.clear();
                state.keys_expires_at = None;
            }
            state.ds_in_parent = ds_values;
            state.insecure = false;
            state.ds_expires_at = Some(deadline);
        });
        DnssecVerdict::Secure
    }

    /// Record the DNSKEY rrset of `zone`. One of `rrsigs` must verify the
    /// rrset under a key matched by the zone's verified DS (the root's
    /// DS are the compiled-in anchors). Returns:
    /// * `Secure` — keys validated and stored;
    /// * `Bogus` — a DS exists but no key matches it or no signature verifies;
    /// * `Insecure` — no DS known for the zone; nothing stored.
    pub fn record_dnskey_rrset(
        &self,
        zone: &Name,
        records: &[Record],
        rrsigs: &[RRSIG],
    ) -> DnssecVerdict {
        self.record_dnskey_rrset_at(zone, records, rrsigs, unix_now())
    }

    pub(crate) fn record_dnskey_rrset_at(
        &self,
        zone: &Name,
        records: &[Record],
        rrsigs: &[RRSIG],
        now: SerialNumber,
    ) -> DnssecVerdict {
        let new_dnskeys: Vec<DNSKEY> = records
            .iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) if r.name == *zone => {
                    Some(dnskey.clone())
                }
                _ => None,
            })
            .collect();
        if new_dnskeys.is_empty() {
            return DnssecVerdict::Bogus;
        }

        let ds_in_parent = self
            .zone(zone)
            .map(|state| state.ds_in_parent)
            .unwrap_or_default();
        if ds_in_parent.is_empty() {
            // No DS: the keys cannot be authenticated. Storing them would
            // let an attacker pre-poison the cache.
            return DnssecVerdict::Insecure;
        }

        // Secure entry points: keys a DS points to. The rrset must be
        // signed by one of them.
        let entry_points: Vec<DNSKEY> = new_dnskeys
            .iter()
            .filter(|key| {
                ds_in_parent
                    .iter()
                    .any(|ds| ds.covers(zone, key).unwrap_or(false))
            })
            .cloned()
            .collect();
        let sig_refs: Vec<&RRSIG> = rrsigs.iter().collect();
        let Some(rrsig) = verify_with_keys(
            &entry_points,
            zone,
            zone,
            DNSClass::IN,
            &sig_refs,
            records,
            now,
        ) else {
            return DnssecVerdict::Bogus;
        };

        let deadline = trust_deadline(records, rrsig, now);
        self.update_zone(zone, |state| {
            if state.ds_in_parent.is_empty() {
                // Evicted or expired meanwhile: keep the DS we verified with.
                state.ds_in_parent = ds_in_parent;
            }
            state.dnskeys = new_dnskeys;
            state.keys_expires_at = Some(deadline);
        });
        DnssecVerdict::Secure
    }

    /// Record that `child_zone` is an insecure delegation of
    /// `parent_zone`, if `authority` (a referral, or a DS NODATA answer)
    /// carries a signed NSEC/NSEC3 proof that the child has no DS.
    ///
    /// Returns `Insecure` when the proof verified (and is stored) or when
    /// the parent itself has no validated keys (nothing to prove), and
    /// `Bogus` when the parent is signed but no valid proof is present:
    /// an attacker may have stripped the DS from the referral.
    pub fn record_insecure_delegation(
        &self,
        parent_zone: &Name,
        child_zone: &Name,
        authority: &[Record],
    ) -> DnssecVerdict {
        let now = unix_now();
        let Some(ZoneStatus::Secure(parent_keys)) = self.zone_status(parent_zone) else {
            return DnssecVerdict::Insecure;
        };
        if !parent_zone.zone_of(child_zone) || parent_zone == child_zone {
            return DnssecVerdict::Bogus;
        }
        match prove_no_ds(&parent_keys, parent_zone, child_zone, authority, now) {
            Some(deadline) => {
                self.update_zone(child_zone, |state| {
                    state.ds_in_parent.clear();
                    state.dnskeys.clear();
                    state.keys_expires_at = None;
                    state.insecure = true;
                    state.ds_expires_at = Some(deadline);
                });
                DnssecVerdict::Insecure
            }
            None => DnssecVerdict::Bogus,
        }
    }

    /// Verify one rrset (all records of `owner`/type) against the zone
    /// that must have signed it.
    fn validate_rrset(
        &self,
        owner: &Name,
        rtype: RecordType,
        dns_class: DNSClass,
        records: &[Record],
        rrsigs: &[&RRSIG],
        now: SerialNumber,
    ) -> DnssecVerdict {
        match self.closest_zone(&signing_lookup_name(owner, rtype)) {
            None | Some((_, ZoneStatus::Insecure)) => DnssecVerdict::Insecure,
            Some((_, ZoneStatus::Broken)) => DnssecVerdict::Bogus,
            Some((zone, ZoneStatus::Secure(keys))) => {
                // Under a signed zone a missing or unverifiable RRSIG is
                // exactly what stripping or forging looks like.
                match verify_with_keys(&keys, &zone, owner, dns_class, rrsigs, records, now) {
                    Some(_) => DnssecVerdict::Secure,
                    None => DnssecVerdict::Bogus,
                }
            }
        }
    }

    /// Top-level entry point invoked by `handle_query`.
    ///
    /// Every answer rrset is validated against its closest known zone;
    /// NXDOMAIN and NODATA (also at the end of a CNAME chain) must carry a
    /// verified NSEC/NSEC3 denial when that zone is signed. Any `Bogus`
    /// rrset makes the whole response `Bogus`; it is `Secure` only when
    /// everything validated, `Insecure` otherwise.
    pub fn validate_message_for(
        &self,
        message: &Message,
        qname: &Name,
        qtype: RecordType,
    ) -> DnssecVerdict {
        self.validate_message_for_at(message, qname, qtype, unix_now())
    }

    pub(crate) fn validate_message_for_at(
        &self,
        message: &Message,
        qname: &Name,
        qtype: RecordType,
        now: SerialNumber,
    ) -> DnssecVerdict {
        let positive = self.validate_answers(&message.answers, now);
        if positive == Some(DnssecVerdict::Bogus) {
            return DnssecVerdict::Bogus;
        }

        let terminal = cname_terminal(&message.answers, qname, qtype);
        let rcode = message.metadata.response_code;
        let is_nxdomain = rcode == ResponseCode::NXDomain;
        let is_nodata = rcode == ResponseCode::NoError
            && !message.answers.iter().any(|r| {
                r.name == terminal
                    && (r.record_type() == qtype
                        || (qtype == RecordType::ANY && r.record_type() != RecordType::RRSIG))
            });
        if !is_nxdomain && !is_nodata {
            return positive.unwrap_or(DnssecVerdict::Insecure);
        }

        let denial = self.validate_denial(message, &terminal, qtype, is_nxdomain, now);
        match (positive, denial) {
            (_, DnssecVerdict::Bogus) => DnssecVerdict::Bogus,
            (None | Some(DnssecVerdict::Secure), DnssecVerdict::Secure) => DnssecVerdict::Secure,
            _ => DnssecVerdict::Insecure,
        }
    }

    /// Validate every rrset of an answer section; `None` when it holds
    /// no data (only RRSIGs or nothing).
    fn validate_answers(&self, answers: &[Record], now: SerialNumber) -> Option<DnssecVerdict> {
        let mut rrsets: Vec<(&Name, RecordType, DNSClass)> = Vec::new();
        for record in answers {
            let key = (&record.name, record.record_type(), record.dns_class);
            if key.1 != RecordType::RRSIG && !rrsets.contains(&key) {
                rrsets.push(key);
            }
        }

        let mut overall: Option<DnssecVerdict> = None;
        for (owner, rtype, dns_class) in rrsets {
            let records: Vec<Record> = answers
                .iter()
                .filter(|r| r.name == *owner && r.record_type() == rtype)
                .cloned()
                .collect();
            let rrsigs = rrsigs_for(answers, owner, rtype);
            let verdict = self.validate_rrset(owner, rtype, dns_class, &records, &rrsigs, now);
            overall = Some(match (overall, verdict) {
                (_, DnssecVerdict::Bogus) => return Some(DnssecVerdict::Bogus),
                (None | Some(DnssecVerdict::Secure), DnssecVerdict::Secure) => {
                    DnssecVerdict::Secure
                }
                _ => DnssecVerdict::Insecure,
            });
        }
        overall
    }

    /// Validate the denial proof for `qname` / `qtype` in `message`'s
    /// authority section.
    ///
    /// Returns `Insecure` when no signed zone encloses `qname`, `Bogus`
    /// when one does (or its chain is broken) and the proof is missing,
    /// badly formed or unverified, `Secure` when the proof holds.
    pub fn validate_negative_answer(
        &self,
        message: &Message,
        qname: &Name,
        qtype: RecordType,
    ) -> DnssecVerdict {
        let is_nxdomain = message.metadata.response_code == ResponseCode::NXDomain;
        self.validate_denial(message, qname, qtype, is_nxdomain, unix_now())
    }

    fn validate_denial(
        &self,
        message: &Message,
        qname: &Name,
        qtype: RecordType,
        is_nxdomain: bool,
        now: SerialNumber,
    ) -> DnssecVerdict {
        let (signing_zone, keys) = match self.closest_zone(&signing_lookup_name(qname, qtype)) {
            None | Some((_, ZoneStatus::Insecure)) => return DnssecVerdict::Insecure,
            Some((_, ZoneStatus::Broken)) => return DnssecVerdict::Bogus,
            Some((zone, ZoneStatus::Secure(keys))) => (zone, keys),
        };

        // A real authoritative serves NSEC or NSEC3 per zone, never both.
        let nsec_records = collect_nsec(&message.authorities);
        if !nsec_records.is_empty() {
            return validate_nsec_denial(
                &keys,
                &signing_zone,
                &message.authorities,
                qname,
                qtype,
                is_nxdomain,
                &nsec_records,
                now,
            );
        }
        let nsec3_records = collect_nsec3(&message.authorities);
        if !nsec3_records.is_empty() {
            return validate_nsec3_denial(
                &keys,
                &signing_zone,
                &message.authorities,
                qname,
                qtype,
                is_nxdomain,
                &nsec3_records,
                now,
            );
        }
        // Signed zone, negative answer, no denial records.
        DnssecVerdict::Bogus
    }
}

impl ZoneTrustState {
    /// True when nothing in this state is still trusted at `now`.
    fn is_expired_at(&self, now: Instant) -> bool {
        let alive = |deadline: Option<Instant>| deadline.is_none_or(|at| at > now);
        let ds_left = alive(self.ds_expires_at) && (!self.ds_in_parent.is_empty() || self.insecure);
        let keys_left = alive(self.keys_expires_at) && !self.dnskeys.is_empty();
        !ds_left && !keys_left
    }
}

/// Last name of the CNAME chain starting at `qname` in `answers`; the
/// name a negative answer is about. `qname` itself for CNAME/ANY queries.
fn cname_terminal(answers: &[Record], qname: &Name, qtype: RecordType) -> Name {
    let mut terminal = qname.clone();
    if matches!(qtype, RecordType::CNAME | RecordType::ANY) {
        return terminal;
    }
    // Each hop consumes a distinct record, bounding in-message loops.
    for _ in 0..answers.len() {
        let next = answers.iter().find_map(|r| match &r.data {
            RData::CNAME(target) if r.name == terminal => Some(target.0.clone()),
            _ => None,
        });
        match next {
            Some(target) => terminal = target,
            None => break,
        }
    }
    terminal
}

// ---------------------------------------------------------------------------
// NSEC / NSEC3 authenticated denial
// ---------------------------------------------------------------------------

/// NSEC denial (RFC 4035 §5.4), simplified: one verified NSEC covering
/// the qname interval (NXDOMAIN) or sitting at the qname with qtype
/// absent from its type map (NODATA). Wildcard-denial NSECs are not
/// required. The zone is signed, so anything short of a verified proof
/// is `Bogus`.
#[allow(clippy::too_many_arguments)]
fn validate_nsec_denial(
    keys: &[DNSKEY],
    signing_zone: &Name,
    authority: &[Record],
    qname: &Name,
    qtype: RecordType,
    is_nxdomain: bool,
    nsec_records: &[(Record, NSEC)],
    now: SerialNumber,
) -> DnssecVerdict {
    for (record, nsec) in nsec_records {
        if !nsec_verified(keys, signing_zone, authority, record, RecordType::NSEC, now) {
            continue;
        }
        let proven = if is_nxdomain {
            nsec_covers_name(&record.name, nsec.next_domain_name(), qname)
        } else {
            record.name == *qname && !nsec.type_set().contains(qtype)
        };
        if proven {
            return DnssecVerdict::Secure;
        }
    }
    DnssecVerdict::Bogus
}

/// NSEC3 denial (RFC 5155), same simplification as the NSEC path: the
/// qname's hash inside one verified NSEC3 interval (NXDOMAIN) or equal to
/// an NSEC3 owner whose type map omits qtype (NODATA). Closest-encloser
/// and wildcard proofs are not required.
#[allow(clippy::too_many_arguments)]
fn validate_nsec3_denial(
    keys: &[DNSKEY],
    signing_zone: &Name,
    authority: &[Record],
    qname: &Name,
    qtype: RecordType,
    is_nxdomain: bool,
    nsec3_records: &[(Record, NSEC3)],
    now: SerialNumber,
) -> DnssecVerdict {
    for (record, nsec3) in nsec3_records {
        if !nsec_verified(
            keys,
            signing_zone,
            authority,
            record,
            RecordType::NSEC3,
            now,
        ) {
            continue;
        }
        let Some((owner_hash, qname_hash)) = nsec3_hashes(nsec3, record, signing_zone, qname)
        else {
            continue;
        };
        let proven = if is_nxdomain {
            hash_in_range(&owner_hash, nsec3.next_hashed_owner_name(), &qname_hash)
        } else {
            owner_hash == qname_hash && !nsec3.type_set().contains(qtype)
        };
        if proven {
            return DnssecVerdict::Secure;
        }
    }
    DnssecVerdict::Bogus
}

/// Signed proof that `child` has no DS, served by `parent`: an NSEC at
/// the child (NS set, DS absent), an NSEC3 matching the child's hash
/// (NS set, DS absent), or an opt-out NSEC3 covering the hash of the
/// child or of an ancestor below the parent (RFC 5155 §6, opt-out spans
/// only ever skip unsigned delegations). Returns the proof's deadline.
fn prove_no_ds(
    keys: &[DNSKEY],
    parent: &Name,
    child: &Name,
    authority: &[Record],
    now: SerialNumber,
) -> Option<Instant> {
    let verified = |record: &Record, rtype: RecordType| {
        let rrsigs = rrsigs_for(authority, &record.name, rtype);
        let owned = rrset_at(authority, &record.name, rtype);
        verify_with_keys(
            keys,
            parent,
            &record.name,
            record.dns_class,
            &rrsigs,
            &owned,
            now,
        )
        .map(|rrsig| trust_deadline(&owned, rrsig, now))
    };

    for (record, nsec) in collect_nsec(authority) {
        if record.name != *child {
            continue;
        }
        let types = nsec.type_set();
        if types.contains(RecordType::NS)
            && !types.contains(RecordType::DS)
            && let Some(deadline) = verified(&record, RecordType::NSEC)
        {
            return Some(deadline);
        }
    }

    // Child and its ancestors strictly below the parent: the "next
    // closer" name of an opt-out proof is one of them.
    let mut candidates = Vec::new();
    let mut name = child.clone();
    while name != *parent && parent.zone_of(&name) {
        candidates.push(name.clone());
        name = name.base_name();
    }

    for (record, nsec3) in collect_nsec3(authority) {
        let Some((owner_hash, child_hash)) = nsec3_hashes(&nsec3, &record, parent, child) else {
            continue;
        };
        let types = nsec3.type_set();
        let exact = owner_hash == child_hash
            && types.contains(RecordType::NS)
            && !types.contains(RecordType::DS);
        let opt_out = nsec3.opt_out()
            && candidates.iter().any(|candidate| {
                nsec3_hash(&nsec3, candidate).is_some_and(|hash| {
                    hash_in_range(&owner_hash, nsec3.next_hashed_owner_name(), &hash)
                })
            });
        if (exact || opt_out)
            && let Some(deadline) = verified(&record, RecordType::NSEC3)
        {
            return Some(deadline);
        }
    }
    None
}

/// True when the NSEC/NSEC3 rrset at `record`'s owner verifies under
/// `keys` as signed by `signing_zone`.
fn nsec_verified(
    keys: &[DNSKEY],
    signing_zone: &Name,
    authority: &[Record],
    record: &Record,
    rtype: RecordType,
    now: SerialNumber,
) -> bool {
    let rrsigs = rrsigs_for(authority, &record.name, rtype);
    let owned = rrset_at(authority, &record.name, rtype);
    verify_with_keys(
        keys,
        signing_zone,
        &record.name,
        record.dns_class,
        &rrsigs,
        &owned,
        now,
    )
    .is_some()
}

/// SHA-1 NSEC3 hash of `name` with `nsec3`'s salt and iterations; `None`
/// for any other (undefined) hash algorithm.
fn nsec3_hash(nsec3: &NSEC3, name: &Name) -> Option<Vec<u8>> {
    let algorithm = nsec3.hash_algorithm();
    if algorithm != Nsec3HashAlgorithm::SHA1 {
        return None;
    }
    algorithm
        .hash(nsec3.salt(), name, nsec3.iterations())
        .ok()
        .map(|digest| digest.as_ref().to_vec())
}

/// `(owner hash, hash of name)` for one NSEC3 record of `zone`.
fn nsec3_hashes(
    nsec3: &NSEC3,
    record: &Record,
    zone: &Name,
    name: &Name,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let owner_hash = extract_nsec3_owner_hash(&record.name, zone)?;
    Some((owner_hash, nsec3_hash(nsec3, name)?))
}

/// Walk `records` and collect every NSEC in lock-step with its
/// owning [`Record`] so the caller still has the owner name + TTL.
fn collect_nsec(records: &[Record]) -> Vec<(Record, NSEC)> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::NSEC(nsec)) => Some((r.clone(), nsec.clone())),
            _ => None,
        })
        .collect()
}

fn collect_nsec3(records: &[Record]) -> Vec<(Record, NSEC3)> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => Some((r.clone(), nsec3.clone())),
            _ => None,
        })
        .collect()
}

/// Every RRSIG in `records` covering `record_type` at `owner`.
fn rrsigs_for<'a>(records: &'a [Record], owner: &Name, record_type: RecordType) -> Vec<&'a RRSIG> {
    records
        .iter()
        .filter(|r| r.name == *owner)
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) if sig.input().type_covered == record_type => {
                Some(sig)
            }
            _ => None,
        })
        .collect()
}

/// Every record of `record_type` at `owner` (the rrset a signature covers).
fn rrset_at(records: &[Record], owner: &Name, record_type: RecordType) -> Vec<Record> {
    records
        .iter()
        .filter(|r| r.name == *owner && r.record_type() == record_type)
        .cloned()
        .collect()
}

/// Canonical-order check: does `nsec_owner ≤ qname < nsec_next`?
/// Handles the wrap-around case where `nsec_owner > nsec_next` (the
/// final NSEC at the zone, pointing at the apex).
pub fn nsec_covers_name(nsec_owner: &Name, nsec_next: &Name, qname: &Name) -> bool {
    if nsec_owner < nsec_next {
        nsec_owner < qname && qname < nsec_next
    } else {
        // Wrap-around: anything strictly above owner OR strictly below
        // next satisfies the interval. The "above owner" side is what
        // covers names alphabetically *after* the last NSEC in the zone.
        nsec_owner < qname || qname < nsec_next
    }
}

/// Pull the first label of an NSEC3 owner name and base32hex-decode it
/// into the original hash bytes. Returns `None` if the label isn't a
/// valid base32hex value (NSEC3 owners always are; this is paranoid).
fn extract_nsec3_owner_hash(owner: &Name, signing_zone: &Name) -> Option<Vec<u8>> {
    if owner.num_labels() == 0 || owner.num_labels() <= signing_zone.num_labels() {
        return None;
    }
    let label = owner.iter().next()?;
    base32hex_decode(label)
}

/// Strict base32hex (RFC 4648 §7) — uppercase digits 0-9 then A-V. We
/// roll a tiny decoder rather than pull in a dependency for one fixed
/// alphabet at a single call site.
fn base32hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(input.len() * 5 / 8 + 1);
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in input {
        let v = match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'V' => byte - b'A' + 10,
            b'a'..=b'v' => byte - b'a' + 10,
            _ => return None,
        } as u64;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// Does the byte slice `q` sit inside the NSEC3 interval (`owner`,
/// `next`)? Same wrap-around rule as NSEC, but the comparison is byte-
/// wise rather than canonical-name-wise.
pub fn hash_in_range(owner: &[u8], next: &[u8], q: &[u8]) -> bool {
    use std::cmp::Ordering::*;
    let oq = owner.cmp(q);
    let qn = q.cmp(next);
    let on = owner.cmp(next);
    if on == Less {
        oq == Less && qn == Less
    } else {
        // Wrap-around or equal endpoints.
        oq == Less || qn == Less
    }
}

// ---------------------------------------------------------------------------
// Harvest helpers
// ---------------------------------------------------------------------------

/// The `rtype` rrset at `owner` in `records`, with every RRSIG covering
/// it. `None` when the rrset is absent or unsigned: an unsigned rrset
/// is no chain progress, the validator decides what that means.
pub fn extract_signed_rrset(
    records: &[Record],
    owner: &Name,
    rtype: RecordType,
) -> Option<(Vec<Record>, Vec<RRSIG>)> {
    let rrset = rrset_at(records, owner, rtype);
    let rrsigs: Vec<RRSIG> = rrsigs_for(records, owner, rtype)
        .into_iter()
        .cloned()
        .collect();
    (!rrset.is_empty() && !rrsigs.is_empty()).then_some((rrset, rrsigs))
}

/// Pull the DS rrset for `child_zone` out of a referral's authority
/// section, with the RRSIGs covering it. `None` for an insecure
/// delegation (no DS) or an unsigned DS rrset.
pub fn extract_ds_rrset_from_authority(
    message: &Message,
    child_zone: &Name,
) -> Option<(Vec<Record>, Vec<RRSIG>)> {
    extract_signed_rrset(&message.authorities, child_zone, RecordType::DS)
}

/// Pull the DNSKEY rrset of `zone` out of a DNSKEY response's answer
/// section, with the RRSIGs covering it. `None` if either is missing.
pub fn extract_dnskey_rrset_from_answers(
    message: &Message,
    zone: &Name,
) -> Option<(Vec<Record>, Vec<RRSIG>)> {
    extract_signed_rrset(&message.answers, zone, RecordType::DNSKEY)
}

/// RRSIG signer names in `records`, deduplicated.
pub fn rrsig_signers(records: &[Record]) -> Vec<Name> {
    let mut signers: Vec<Name> = Vec::new();
    for record in records {
        if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = &record.data {
            let signer = &sig.input().signer_name;
            if !signers.contains(signer) {
                signers.push(signer.clone());
            }
        }
    }
    signers
}

/// Signing fixtures shared by the validator and resolver tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::time::Duration;

    use hickory_resolver::proto::dnssec::crypto::EcdsaSigningKey;
    use hickory_resolver::proto::dnssec::{DnssecSigner, PublicKeyBuf, SigningKey};
    use hickory_resolver::proto::rr::RecordSet;
    use hickory_resolver::proto::rr::rdata::A;
    use time::OffsetDateTime;

    use super::*;

    pub(crate) fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    /// A signed test zone: one ECDSA P-256 key used as both KSK and ZSK.
    pub(crate) struct TestZone {
        pub(crate) zone: Name,
        signer: DnssecSigner,
    }

    impl TestZone {
        /// Root trust anchor pointing at this zone's key (tests only:
        /// the digest is leaked to get the `'static` the type needs).
        pub(crate) fn as_root_anchor(&self) -> RootTrustAnchor {
            let ds = self.ds();
            RootTrustAnchor {
                key_tag: ds.key_tag(),
                algorithm: ds.algorithm(),
                digest_type: ds.digest_type(),
                digest: Box::leak(ds.digest().to_vec().into_boxed_slice()),
            }
        }

        pub(crate) fn new(zone: &str) -> Self {
            let zone = name(zone);
            let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
            let key = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).unwrap();
            let public: PublicKeyBuf = key.to_public_key().unwrap();
            // Flags 257 = ZONE_KEY | SEP.
            let dnskey = DNSKEY::with_flags(257, public);
            let signer = DnssecSigner::new(
                dnskey,
                Box::new(key),
                zone.clone(),
                Duration::from_secs(3600),
            );
            Self { zone, signer }
        }

        pub(crate) fn dnskey(&self) -> DNSKEY {
            self.signer.dnskey().clone()
        }

        /// DS for this zone's key, as the parent would publish it.
        pub(crate) fn ds(&self) -> DS {
            let key = self.dnskey();
            let digest = key.to_digest(&self.zone, DigestType::SHA256).unwrap();
            DS::new(
                key.calculate_key_tag().unwrap(),
                key.algorithm(),
                DigestType::SHA256,
                digest.as_ref().to_vec(),
            )
        }

        /// Sign one rrset; the signature is valid for an hour from `inception`.
        pub(crate) fn sign_at(&self, records: &[Record], inception: OffsetDateTime) -> RRSIG {
            let first = &records[0];
            let mut rrset = RecordSet::with_ttl(first.name.clone(), first.record_type(), first.ttl);
            for record in records {
                rrset.add_rdata(record.data.clone());
            }
            RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &self.signer).unwrap()
        }

        pub(crate) fn sign(&self, records: &[Record]) -> RRSIG {
            self.sign_at(
                records,
                OffsetDateTime::now_utc() - time::Duration::minutes(5),
            )
        }

        /// `records` followed by the RRSIG record covering them.
        pub(crate) fn signed(&self, records: Vec<Record>) -> Vec<Record> {
            let rrsig = self.sign(&records);
            let owner = records[0].name.clone();
            let mut out = records;
            out.push(rrsig_record(owner, rrsig));
            out
        }

        pub(crate) fn dnskey_rrset(&self) -> Vec<Record> {
            vec![Record::from_rdata(
                self.zone.clone(),
                3600,
                RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey())),
            )]
        }

        /// Mark this zone Secure in `validator`, bypassing the chain.
        pub(crate) fn trust_in(&self, validator: &RecursiveDnssecValidator) {
            validator.seed_zone_for_test(
                self.zone.clone(),
                ZoneTrustState {
                    dnskeys: vec![self.dnskey()],
                    ..ZoneTrustState::default()
                },
            );
        }
    }

    pub(crate) fn rrsig_record(owner: Name, rrsig: RRSIG) -> Record {
        Record::from_rdata(owner, 3600, RData::DNSSEC(DNSSECRData::RRSIG(rrsig)))
    }

    pub(crate) fn a_record(owner: &str, ip: [u8; 4]) -> Record {
        Record::from_rdata(name(owner), 300, RData::A(A(std::net::Ipv4Addr::from(ip))))
    }

    pub(crate) fn ds_records(child: &Name, ds: &[DS]) -> Vec<Record> {
        ds.iter()
            .map(|d| {
                Record::from_rdata(
                    child.clone(),
                    3600,
                    RData::DNSSEC(DNSSECRData::DS(d.clone())),
                )
            })
            .collect()
    }

    pub(crate) fn nsec_record(owner: &Name, next: &Name, types: &[RecordType]) -> Record {
        let nsec = NSEC::new(next.clone(), types.iter().copied());
        Record::from_rdata(owner.clone(), 3600, RData::DNSSEC(DNSSECRData::NSEC(nsec)))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hickory_resolver::proto::dnssec::PublicKeyBuf;
    use hickory_resolver::proto::rr::rdata::CNAME;
    use time::OffsetDateTime;

    use super::test_support::*;
    use super::*;

    /// RRSIG timestamp for midnight UTC on the given day.
    fn serial_at(year: i32, month: time::Month, day: u8) -> SerialNumber {
        let date = time::Date::from_calendar_date(year, month, day).unwrap();
        let seconds = date.midnight().assume_utc().unix_timestamp();
        SerialNumber::new(seconds as u32)
    }

    fn base32hex(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
        let mut out = String::new();
        let mut buffer: u32 = 0;
        let mut bits = 0;
        for &byte in bytes {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    fn nsec3_hash_of(target: &Name) -> Vec<u8> {
        Nsec3HashAlgorithm::SHA1
            .hash(&[], target, 0)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    /// NSEC3 record of `zone` owned by `owner_hash`, pointing at `next_hash`.
    fn nsec3_record(
        zone: &Name,
        owner_hash: &[u8],
        next_hash: Vec<u8>,
        opt_out: bool,
        types: &[RecordType],
    ) -> Record {
        let owner = Name::from_ascii(format!("{}.{zone}", base32hex(owner_hash))).unwrap();
        let nsec3 = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            opt_out,
            0,
            Vec::new(),
            next_hash,
            types.iter().copied(),
        );
        Record::from_rdata(owner, 3600, RData::DNSSEC(DNSSECRData::NSEC3(nsec3)))
    }

    fn message(rcode: ResponseCode, answers: Vec<Record>, authority: Vec<Record>) -> Message {
        let mut msg = Message::query();
        msg.metadata.response_code = rcode;
        for record in answers {
            msg.add_answer(record);
        }
        for record in authority {
            msg.add_authority(record);
        }
        msg
    }

    fn rrsig_of(record: &Record) -> RRSIG {
        match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => rrsig.clone(),
            _ => panic!("not an RRSIG"),
        }
    }

    // -----------------------------------------------------------------
    // Root trust anchors (E1 point 2)
    // -----------------------------------------------------------------

    fn iana_key(hex: &str) -> DNSKEY {
        let bytes = (0..hex.trim().len())
            .step_by(2)
            .map(|idx| u8::from_str_radix(&hex.trim()[idx..idx + 2], 16).unwrap())
            .collect();
        DNSKEY::with_flags(257, PublicKeyBuf::new(bytes, Algorithm::RSASHA256))
    }

    fn assert_anchor_matches(anchor: &RootTrustAnchor, public_key_hex: &str) {
        let key = iana_key(public_key_hex);
        assert_eq!(key.calculate_key_tag().unwrap(), anchor.key_tag);
        let digest = key.to_digest(&Name::root(), anchor.digest_type).unwrap();
        assert_eq!(digest.as_ref(), anchor.digest);
    }

    #[test]
    fn ksk_2017_digest_matches_iana_public_key() {
        // Public key from IANA root-anchors.xml, hex-encoded.
        assert_anchor_matches(
            &ROOT_KSK_2017,
            include_str!("../../tests/fixtures/root_ksk_2017.pub.hex"),
        );
    }

    #[test]
    fn ksk_2024_digest_matches_iana_public_key() {
        assert_anchor_matches(
            &ROOT_KSK_2024,
            include_str!("../../tests/fixtures/root_ksk_2024.pub.hex"),
        );
    }

    #[test]
    fn default_validator_trusts_both_root_ksks_and_nothing_else() {
        let v = RecursiveDnssecValidator::default();
        let root = v.zone(&Name::root()).expect("root must be seeded");
        let tags: Vec<u16> = root.ds_in_parent.iter().map(|ds| ds.key_tag()).collect();
        assert_eq!(tags, [20326, 38696]);
        assert!(
            root.dnskeys.is_empty(),
            "root keys are fetched, never assumed"
        );
        assert!(v.zone(&name("example.com.")).is_none());
        // DS without keys: everything below the root is unverifiable
        // until the root DNSKEY is fetched and validated.
        assert!(v.needs_keys(&Name::root()));
    }

    /// Root DNSKEY response captured from a.root-servers.net on
    /// 2026-11-17: signed by KSK-2024 only, valid 2026-11-10..2026-12-01.
    fn real_root_dnskey() -> (Vec<Record>, Vec<RRSIG>) {
        let bytes = include_bytes!("../../tests/fixtures/root_dnskey_response.bin");
        let msg = Message::from_vec(bytes).unwrap();
        extract_dnskey_rrset_from_answers(&msg, &Name::root()).expect("signed DNSKEY rrset")
    }

    #[test]
    fn real_root_dnskey_validates_against_compiled_anchors() {
        let v = RecursiveDnssecValidator::default();
        let (records, rrsigs) = real_root_dnskey();
        let now = serial_at(2026, time::Month::November, 17);
        assert_eq!(
            v.record_dnskey_rrset_at(&Name::root(), &records, &rrsigs, now),
            DnssecVerdict::Secure
        );
        assert_eq!(v.zone(&Name::root()).unwrap().dnskeys.len(), 3);
        assert!(!v.needs_keys(&Name::root()));
    }

    #[test]
    fn real_root_dnskey_is_bogus_with_ksk_2017_alone() {
        // The rollover moved signing to KSK-2024: a KSK-2017-only build
        // can no longer anchor anything.
        let v = RecursiveDnssecValidator::with_root_anchors(&[ROOT_KSK_2017]);
        let (records, rrsigs) = real_root_dnskey();
        let now = serial_at(2026, time::Month::November, 17);
        assert_eq!(
            v.record_dnskey_rrset_at(&Name::root(), &records, &rrsigs, now),
            DnssecVerdict::Bogus
        );
    }

    #[test]
    fn real_root_dnskey_is_bogus_outside_its_validity_window() {
        let (records, rrsigs) = real_root_dnskey();
        for now in [
            serial_at(2026, time::Month::November, 9),
            serial_at(2026, time::Month::December, 2),
        ] {
            let v = RecursiveDnssecValidator::default();
            assert_eq!(
                v.record_dnskey_rrset_at(&Name::root(), &records, &rrsigs, now),
                DnssecVerdict::Bogus
            );
            assert!(v.zone(&Name::root()).unwrap().dnskeys.is_empty());
        }
    }

    // -----------------------------------------------------------------
    // DS and DNSKEY hand-off (E1 points 2, 3, 4)
    // -----------------------------------------------------------------

    #[test]
    fn ds_not_stored_when_parent_keys_are_unknown() {
        // Root has the anchors but no validated keys yet: a DS "signed by
        // the root" cannot be authenticated and must not be stored.
        let v = RecursiveDnssecValidator::default();
        let child = TestZone::new("com.");
        let records = ds_records(&child.zone, &[child.ds()]);
        let rrsig = TestZone::new(".").sign(&records);
        assert_eq!(
            v.record_ds_for_child(&Name::root(), &child.zone, &records, &[rrsig]),
            DnssecVerdict::Insecure
        );
        assert!(v.zone(&child.zone).is_none());
    }

    #[test]
    fn ds_stored_when_signed_by_parent_keys() {
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("example.");
        let child = TestZone::new("sub.example.");
        parent.trust_in(&v);
        let records = ds_records(&child.zone, &[child.ds()]);
        let rrsig = parent.sign(&records);
        assert_eq!(
            v.record_ds_for_child(&parent.zone, &child.zone, &records, &[rrsig]),
            DnssecVerdict::Secure
        );
        assert_eq!(v.zone(&child.zone).unwrap().ds_in_parent, [child.ds()]);
        assert!(v.needs_keys(&child.zone));
    }

    #[test]
    fn ds_bogus_when_not_signed_by_parent() {
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("example.");
        let child = TestZone::new("sub.example.");
        let attacker = TestZone::new("attacker.test.");
        parent.trust_in(&v);
        attacker.trust_in(&v);
        let records = ds_records(&child.zone, &[child.ds()]);
        // Signed by another (even trusted) zone, or by the child itself.
        for signer in [&attacker, &child] {
            let rrsig = signer.sign(&records);
            assert_eq!(
                v.record_ds_for_child(&parent.zone, &child.zone, &records, &[rrsig]),
                DnssecVerdict::Bogus
            );
        }
        // An unsigned DS rrset proves nothing either.
        assert_eq!(
            v.record_ds_for_child(&parent.zone, &child.zone, &records, &[]),
            DnssecVerdict::Bogus
        );
        assert!(v.zone(&child.zone).is_none());
    }

    #[test]
    fn ds_bogus_when_signature_expired() {
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("example.");
        let child = TestZone::new("sub.example.");
        parent.trust_in(&v);
        let records = ds_records(&child.zone, &[child.ds()]);
        let expired = parent.sign_at(
            &records,
            OffsetDateTime::now_utc() - time::Duration::hours(2),
        );
        assert_eq!(
            v.record_ds_for_child(&parent.zone, &child.zone, &records, &[expired]),
            DnssecVerdict::Bogus
        );
    }

    #[test]
    fn dnskey_not_stored_without_ds() {
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        let records = zone.dnskey_rrset();
        let rrsig = zone.sign(&records);
        assert_eq!(
            v.record_dnskey_rrset(&zone.zone, &records, &[rrsig]),
            DnssecVerdict::Insecure
        );
        // No entry is created for an unauthenticated rrset.
        assert!(v.zones.get(&zone.zone).is_none());
    }

    fn validator_with_ds(zone: &TestZone) -> RecursiveDnssecValidator {
        let v = RecursiveDnssecValidator::empty();
        v.seed_zone_for_test(
            zone.zone.clone(),
            ZoneTrustState {
                ds_in_parent: vec![zone.ds()],
                ..ZoneTrustState::default()
            },
        );
        v
    }

    #[test]
    fn dnskey_secure_when_ds_matches() {
        let zone = TestZone::new("example.com.");
        let v = validator_with_ds(&zone);
        let records = zone.dnskey_rrset();
        let rrsig = zone.sign(&records);
        assert_eq!(
            v.record_dnskey_rrset(&zone.zone, &records, &[rrsig]),
            DnssecVerdict::Secure
        );
        assert_eq!(v.zone(&zone.zone).unwrap().dnskeys, [zone.dnskey()]);
    }

    #[test]
    fn dnskey_bogus_when_signed_by_key_outside_ds() {
        // The rrset holds the DS-covered key A and a rogue key B, but
        // only B signed it: the signature must come from an entry point.
        let key_a = TestZone::new("example.com.");
        let key_b = TestZone::new("example.com.");
        let v = validator_with_ds(&key_a);
        let mut records = key_a.dnskey_rrset();
        records.extend(key_b.dnskey_rrset());
        let rrsig = key_b.sign(&records);
        assert_eq!(
            v.record_dnskey_rrset(&key_a.zone, &records, &[rrsig]),
            DnssecVerdict::Bogus
        );
    }

    #[test]
    fn dnskey_secure_when_any_rrsig_verifies() {
        // Double signature during a rollover: one RRSIG is enough.
        let key_a = TestZone::new("example.com.");
        let key_b = TestZone::new("example.com.");
        let v = validator_with_ds(&key_a);
        let mut records = key_a.dnskey_rrset();
        records.extend(key_b.dnskey_rrset());
        let rrsigs = [key_b.sign(&records), key_a.sign(&records)];
        assert_eq!(
            v.record_dnskey_rrset(&key_a.zone, &records, &rrsigs),
            DnssecVerdict::Secure
        );
    }

    #[test]
    fn dnskey_bogus_when_rrsig_expired_or_not_yet_valid() {
        let zone = TestZone::new("example.com.");
        let records = zone.dnskey_rrset();
        for inception in [
            OffsetDateTime::now_utc() - time::Duration::hours(2),
            OffsetDateTime::now_utc() + time::Duration::hours(1),
        ] {
            let v = validator_with_ds(&zone);
            let rrsig = zone.sign_at(&records, inception);
            assert_eq!(
                v.record_dnskey_rrset(&zone.zone, &records, &[rrsig]),
                DnssecVerdict::Bogus
            );
        }
    }

    // -----------------------------------------------------------------
    // Answer validation (E1 points 1, 3, 4)
    // -----------------------------------------------------------------

    fn validate(v: &RecursiveDnssecValidator, msg: &Message, qname: &str) -> DnssecVerdict {
        v.validate_message_for(msg, &name(qname), RecordType::A)
    }

    #[test]
    fn signed_answer_is_secure() {
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        zone.trust_in(&v);
        let answers = zone.signed(vec![a_record("www.example.com.", [1, 2, 3, 4])]);
        let msg = message(ResponseCode::NoError, answers, vec![]);
        assert_eq!(
            validate(&v, &msg, "www.example.com."),
            DnssecVerdict::Secure
        );
    }

    #[test]
    fn stripped_rrsig_under_signed_zone_is_bogus() {
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        zone.trust_in(&v);
        let msg = message(
            ResponseCode::NoError,
            vec![a_record("www.example.com.", [6, 6, 6, 6])],
            vec![],
        );
        assert_eq!(validate(&v, &msg, "www.example.com."), DnssecVerdict::Bogus);
    }

    #[test]
    fn tampered_answer_is_bogus() {
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        zone.trust_in(&v);
        let mut answers = zone.signed(vec![a_record("www.example.com.", [1, 2, 3, 4])]);
        answers[0] = a_record("www.example.com.", [9, 9, 9, 9]);
        let msg = message(ResponseCode::NoError, answers, vec![]);
        assert_eq!(validate(&v, &msg, "www.example.com."), DnssecVerdict::Bogus);
    }

    #[test]
    fn unknown_key_tag_is_bogus() {
        // Same zone name, key the validator never saw.
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        let rogue = TestZone::new("example.com.");
        zone.trust_in(&v);
        let answers = rogue.signed(vec![a_record("www.example.com.", [6, 6, 6, 6])]);
        let msg = message(ResponseCode::NoError, answers, vec![]);
        assert_eq!(validate(&v, &msg, "www.example.com."), DnssecVerdict::Bogus);
    }

    #[test]
    fn expired_or_future_answer_signature_is_bogus() {
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        zone.trust_in(&v);
        let records = vec![a_record("www.example.com.", [1, 2, 3, 4])];
        for inception in [
            OffsetDateTime::now_utc() - time::Duration::hours(2),
            OffsetDateTime::now_utc() + time::Duration::hours(1),
        ] {
            let rrsig = zone.sign_at(&records, inception);
            let mut answers = records.clone();
            answers.push(rrsig_record(name("www.example.com."), rrsig));
            let msg = message(ResponseCode::NoError, answers, vec![]);
            assert_eq!(validate(&v, &msg, "www.example.com."), DnssecVerdict::Bogus);
        }
    }

    #[test]
    fn signer_from_another_zone_is_bogus() {
        // attacker.test is trusted for its own names, not for example.com.
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        let attacker = TestZone::new("attacker.test.");
        zone.trust_in(&v);
        attacker.trust_in(&v);
        let answers = attacker.signed(vec![a_record("www.example.com.", [6, 6, 6, 6])]);
        let msg = message(ResponseCode::NoError, answers, vec![]);
        assert_eq!(validate(&v, &msg, "www.example.com."), DnssecVerdict::Bogus);
    }

    #[test]
    fn signer_must_be_the_closest_known_zone() {
        // sub.example.com is a known signed zone: data below it signed
        // with the parent's key is not acceptable.
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("example.com.");
        let child = TestZone::new("sub.example.com.");
        parent.trust_in(&v);
        child.trust_in(&v);
        let answers = parent.signed(vec![a_record("www.sub.example.com.", [6, 6, 6, 6])]);
        let msg = message(ResponseCode::NoError, answers, vec![]);
        assert_eq!(
            validate(&v, &msg, "www.sub.example.com."),
            DnssecVerdict::Bogus
        );

        let answers = child.signed(vec![a_record("www.sub.example.com.", [1, 2, 3, 4])]);
        let msg = message(ResponseCode::NoError, answers, vec![]);
        assert_eq!(
            validate(&v, &msg, "www.sub.example.com."),
            DnssecVerdict::Secure
        );
    }

    #[test]
    fn unsigned_answer_without_any_chain_is_insecure() {
        let v = RecursiveDnssecValidator::empty();
        let msg = message(
            ResponseCode::NoError,
            vec![a_record("example.com.", [1, 2, 3, 4])],
            vec![],
        );
        assert_eq!(validate(&v, &msg, "example.com."), DnssecVerdict::Insecure);
    }

    #[test]
    fn answer_under_broken_chain_is_bogus() {
        // Verified DS, no validated DNSKEY: the zone is signed and its
        // data cannot be checked, signed or not.
        let zone = TestZone::new("example.com.");
        let v = validator_with_ds(&zone);
        let answers = zone.signed(vec![a_record("www.example.com.", [1, 2, 3, 4])]);
        let msg = message(ResponseCode::NoError, answers, vec![]);
        assert_eq!(validate(&v, &msg, "www.example.com."), DnssecVerdict::Bogus);
    }

    #[test]
    fn answer_under_insecure_delegation_is_insecure() {
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("com.");
        parent.trust_in(&v);
        v.seed_zone_for_test(
            name("unsigned.com."),
            ZoneTrustState {
                insecure: true,
                ..ZoneTrustState::default()
            },
        );
        let msg = message(
            ResponseCode::NoError,
            vec![a_record("www.unsigned.com.", [1, 2, 3, 4])],
            vec![],
        );
        assert_eq!(
            validate(&v, &msg, "www.unsigned.com."),
            DnssecVerdict::Insecure
        );
    }

    #[test]
    fn cname_chain_across_signed_zones() {
        let v = RecursiveDnssecValidator::empty();
        let first = TestZone::new("example.com.");
        let second = TestZone::new("cdn.net.");
        first.trust_in(&v);
        second.trust_in(&v);
        let cname = Record::from_rdata(
            name("www.example.com."),
            300,
            RData::CNAME(CNAME(name("edge.cdn.net."))),
        );
        let mut answers = first.signed(vec![cname.clone()]);
        answers.extend(second.signed(vec![a_record("edge.cdn.net.", [1, 2, 3, 4])]));
        let msg = message(ResponseCode::NoError, answers, vec![]);
        assert_eq!(
            validate(&v, &msg, "www.example.com."),
            DnssecVerdict::Secure
        );

        // Target data stripped: the chain is only as strong as its weakest rrset.
        let mut answers = first.signed(vec![cname]);
        answers.push(a_record("edge.cdn.net.", [6, 6, 6, 6]));
        let msg = message(ResponseCode::NoError, answers, vec![]);
        assert_eq!(validate(&v, &msg, "www.example.com."), DnssecVerdict::Bogus);
    }

    #[test]
    fn ds_answer_is_validated_by_the_parent_zone() {
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("example.com.");
        let child = TestZone::new("sub.example.com.");
        parent.trust_in(&v);
        child.trust_in(&v);
        let answers = parent.signed(ds_records(&child.zone, &[child.ds()]));
        let msg = message(ResponseCode::NoError, answers, vec![]);
        assert_eq!(
            v.validate_message_for(&msg, &child.zone, RecordType::DS),
            DnssecVerdict::Secure
        );
    }

    // -----------------------------------------------------------------
    // Insecure delegation proofs (E1 point 1)
    // -----------------------------------------------------------------

    fn insecure_proof(
        v: &RecursiveDnssecValidator,
        parent: &TestZone,
        child: &Name,
        authority: Vec<Record>,
    ) -> (DnssecVerdict, bool) {
        let verdict = v.record_insecure_delegation(&parent.zone, child, &authority);
        let stored = matches!(v.zone_status(child), Some(ZoneStatus::Insecure));
        (verdict, stored)
    }

    #[test]
    fn nsec_without_ds_bit_proves_insecure_delegation() {
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("com.");
        parent.trust_in(&v);
        let child = name("unsigned.com.");
        let nsec = nsec_record(
            &child,
            &name("zzz.com."),
            &[RecordType::NS, RecordType::NSEC],
        );
        let authority = parent.signed(vec![nsec]);
        assert_eq!(
            insecure_proof(&v, &parent, &child, authority),
            (DnssecVerdict::Insecure, true)
        );
    }

    #[test]
    fn nsec_listing_ds_or_lacking_ns_is_not_a_proof() {
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("com.");
        parent.trust_in(&v);
        let child = name("signed.com.");
        for types in [
            vec![RecordType::NS, RecordType::DS, RecordType::NSEC],
            vec![RecordType::A, RecordType::NSEC],
        ] {
            let nsec = nsec_record(&child, &name("zzz.com."), &types);
            let authority = parent.signed(vec![nsec]);
            assert_eq!(
                insecure_proof(&v, &parent, &child, authority),
                (DnssecVerdict::Bogus, false)
            );
        }
    }

    #[test]
    fn unsigned_or_foreign_nsec_is_not_a_proof() {
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("com.");
        let attacker = TestZone::new("attacker.test.");
        parent.trust_in(&v);
        attacker.trust_in(&v);
        let child = name("unsigned.com.");
        let nsec = nsec_record(
            &child,
            &name("zzz.com."),
            &[RecordType::NS, RecordType::NSEC],
        );
        for authority in [vec![nsec.clone()], attacker.signed(vec![nsec]), vec![]] {
            assert_eq!(
                insecure_proof(&v, &parent, &child, authority),
                (DnssecVerdict::Bogus, false)
            );
        }
    }

    #[test]
    fn nsec3_exact_match_proves_insecure_delegation() {
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("com.");
        parent.trust_in(&v);
        let child = name("unsigned.com.");
        let nsec3 = nsec3_record(
            &parent.zone,
            &nsec3_hash_of(&child),
            vec![0xff; 20],
            false,
            &[RecordType::NS],
        );
        let authority = parent.signed(vec![nsec3]);
        assert_eq!(
            insecure_proof(&v, &parent, &child, authority),
            (DnssecVerdict::Insecure, true)
        );
    }

    #[test]
    fn nsec3_opt_out_span_proves_insecure_delegation() {
        // The usual .com shape: the child has no NSEC3 of its own, an
        // opt-out NSEC3 covers its hash.
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("com.");
        parent.trust_in(&v);
        let child = name("unsigned.com.");
        let covering =
            |opt_out| nsec3_record(&parent.zone, &[0x00; 20], vec![0xff; 20], opt_out, &[]);
        let authority = parent.signed(vec![covering(true)]);
        assert_eq!(
            insecure_proof(&v, &parent, &child, authority),
            (DnssecVerdict::Insecure, true)
        );

        // Without opt-out, a covering NSEC3 says the name does not exist,
        // not that it is an unsigned delegation.
        let v = RecursiveDnssecValidator::empty();
        parent.trust_in(&v);
        let authority = parent.signed(vec![covering(false)]);
        assert_eq!(
            insecure_proof(&v, &parent, &child, authority),
            (DnssecVerdict::Bogus, false)
        );
    }

    #[test]
    fn insecure_parent_needs_no_proof_and_stores_nothing() {
        let v = RecursiveDnssecValidator::empty();
        let child = name("anything.example.");
        assert_eq!(
            v.record_insecure_delegation(&name("example."), &child, &[]),
            DnssecVerdict::Insecure
        );
        assert!(v.zone(&child).is_none());
    }

    // -----------------------------------------------------------------
    // Negative answers
    // -----------------------------------------------------------------

    fn signed_nsec(zone: &TestZone, owner: &str, next: &str, types: &[RecordType]) -> Vec<Record> {
        zone.signed(vec![nsec_record(&name(owner), &name(next), types)])
    }

    #[test]
    fn nsec_covers_name_handles_normal_interval() {
        let owner = name("a.example.");
        let next = name("m.example.");
        assert!(nsec_covers_name(&owner, &next, &name("g.example.")));
        assert!(!nsec_covers_name(&owner, &next, &name("z.example.")));
    }

    #[test]
    fn nsec_covers_name_handles_wrap_around() {
        // Final NSEC in the zone wraps from "z.example." back to the apex.
        let owner = name("z.example.");
        let next = name("example.");
        assert!(nsec_covers_name(&owner, &next, &name("z2.example.")));
    }

    #[test]
    fn negative_answer_without_chain_is_insecure() {
        let v = RecursiveDnssecValidator::empty();
        let msg = message(ResponseCode::NXDomain, vec![], vec![]);
        assert_eq!(
            v.validate_negative_answer(&msg, &name("missing.example."), RecordType::A),
            DnssecVerdict::Insecure
        );
    }

    #[test]
    fn negative_answer_without_denial_in_signed_zone_is_bogus() {
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        zone.trust_in(&v);
        let msg = message(ResponseCode::NXDomain, vec![], vec![]);
        assert_eq!(
            v.validate_negative_answer(&msg, &name("nonexistent.example.com."), RecordType::A),
            DnssecVerdict::Bogus
        );
    }

    #[test]
    fn nxdomain_with_covering_nsec_is_secure() {
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        zone.trust_in(&v);
        let authority = signed_nsec(&zone, "a.example.com.", "z.example.com.", &[RecordType::A]);
        let msg = message(ResponseCode::NXDomain, vec![], authority);
        assert_eq!(validate(&v, &msg, "m.example.com."), DnssecVerdict::Secure);
        // Same proof, name outside the interval.
        assert_eq!(validate(&v, &msg, "zz.example.com."), DnssecVerdict::Bogus);
    }

    #[test]
    fn nodata_with_nsec_at_qname_is_secure() {
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        zone.trust_in(&v);
        let authority = signed_nsec(
            &zone,
            "named.example.com.",
            "z.example.com.",
            &[RecordType::A, RecordType::TXT],
        );
        let msg = message(ResponseCode::NoError, vec![], authority);
        assert_eq!(
            v.validate_message_for(&msg, &name("named.example.com."), RecordType::AAAA),
            DnssecVerdict::Secure
        );
        // A is present in the type map: no NODATA for A.
        assert_eq!(
            validate(&v, &msg, "named.example.com."),
            DnssecVerdict::Bogus
        );
    }

    #[test]
    fn denial_signed_by_wrong_key_is_bogus() {
        // Under a signed zone an unverifiable denial is a forged denial.
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        let attacker = TestZone::new("attacker.test.");
        zone.trust_in(&v);
        let authority = signed_nsec(
            &attacker,
            "a.example.com.",
            "z.example.com.",
            &[RecordType::A],
        );
        let msg = message(ResponseCode::NXDomain, vec![], authority);
        assert_eq!(validate(&v, &msg, "m.example.com."), DnssecVerdict::Bogus);
    }

    #[test]
    fn nxdomain_under_insecure_delegation_is_insecure() {
        let v = RecursiveDnssecValidator::empty();
        TestZone::new("com.").trust_in(&v);
        v.seed_zone_for_test(
            name("unsigned.com."),
            ZoneTrustState {
                insecure: true,
                ..ZoneTrustState::default()
            },
        );
        let msg = message(ResponseCode::NXDomain, vec![], vec![]);
        assert_eq!(
            validate(&v, &msg, "gone.unsigned.com."),
            DnssecVerdict::Insecure
        );
    }

    #[test]
    fn nxdomain_after_cname_validates_the_chain_terminal() {
        let v = RecursiveDnssecValidator::empty();
        let zone = TestZone::new("example.com.");
        zone.trust_in(&v);
        let cname = Record::from_rdata(
            name("www.example.com."),
            300,
            RData::CNAME(CNAME(name("gone.example.com."))),
        );
        let answers = zone.signed(vec![cname]);
        // The NSEC covers the terminal `gone`, not `www` (which exists).
        let authority = signed_nsec(&zone, "a.example.com.", "h.example.com.", &[RecordType::A]);
        let msg = message(ResponseCode::NXDomain, answers.clone(), authority);
        assert_eq!(
            validate(&v, &msg, "www.example.com."),
            DnssecVerdict::Secure
        );

        let msg = message(ResponseCode::NXDomain, answers, vec![]);
        assert_eq!(validate(&v, &msg, "www.example.com."), DnssecVerdict::Bogus);
    }

    #[test]
    fn hash_in_range_handles_normal_and_wrap() {
        assert!(hash_in_range(
            &[0, 0, 0, 10],
            &[0, 0, 0, 80],
            &[0, 0, 0, 40]
        ));
        assert!(!hash_in_range(
            &[0, 0, 0, 10],
            &[0, 0, 0, 80],
            &[0, 0, 0, 90]
        ));
        assert!(hash_in_range(
            &[0, 0, 0, 200],
            &[0, 0, 0, 20],
            &[0, 0, 0, 250]
        ));
        assert!(hash_in_range(
            &[0, 0, 0, 200],
            &[0, 0, 0, 20],
            &[0, 0, 0, 10]
        ));
        assert!(!hash_in_range(
            &[0, 0, 0, 200],
            &[0, 0, 0, 20],
            &[0, 0, 0, 100]
        ));
    }

    #[test]
    fn base32hex_decoder_round_trips() {
        // RFC 4648 §10: "fooba" → "CPNMUOJ1".
        assert_eq!(&base32hex_decode(b"CPNMUOJ1").unwrap()[..5], b"fooba");
        let hash = nsec3_hash_of(&name("example.com."));
        assert_eq!(base32hex_decode(base32hex(&hash).as_bytes()).unwrap(), hash);
    }

    #[test]
    fn base32hex_decoder_rejects_invalid_chars() {
        assert!(base32hex_decode(b"AAAAW").is_none());
        assert!(base32hex_decode(b"AA AA").is_none());
    }

    // -----------------------------------------------------------------
    // Harvest helpers
    // -----------------------------------------------------------------

    #[test]
    fn extract_ds_returns_none_without_signed_ds() {
        let child = name("example.com.");
        let ns = Record::from_rdata(
            child.clone(),
            300,
            RData::NS(hickory_resolver::proto::rr::rdata::NS(name(
                "ns1.example.com.",
            ))),
        );
        let msg = message(ResponseCode::NoError, vec![], vec![ns]);
        assert!(extract_ds_rrset_from_authority(&msg, &child).is_none());
        // DS present but unsigned.
        let zone = TestZone::new("com.");
        let msg = message(
            ResponseCode::NoError,
            vec![],
            ds_records(&child, &[zone.ds()]),
        );
        assert!(extract_ds_rrset_from_authority(&msg, &child).is_none());
    }

    #[test]
    fn extract_ds_keeps_every_signature_and_ignores_other_owners() {
        let parent = TestZone::new("example.com.");
        let other = TestZone::new("example.com.");
        let child = name("sub.example.com.");
        let records = ds_records(&child, &[parent.ds()]);
        let mut authority = parent.signed(records.clone());
        authority.push(rrsig_record(child.clone(), other.sign(&records)));
        let msg = message(ResponseCode::NoError, vec![], authority);
        let (ds, rrsigs) = extract_ds_rrset_from_authority(&msg, &child).unwrap();
        assert_eq!(ds.len(), 1);
        assert_eq!(rrsigs.len(), 2);
        assert!(extract_ds_rrset_from_authority(&msg, &name("other.example.com.")).is_none());
    }

    #[test]
    fn extract_dnskey_requires_a_dnskey_signature() {
        let zone = TestZone::new("example.com.");
        let msg = message(
            ResponseCode::NoError,
            zone.signed(zone.dnskey_rrset()),
            vec![],
        );
        assert!(extract_dnskey_rrset_from_answers(&msg, &zone.zone).is_some());

        // An RRSIG covering another type must not stand in for one.
        let a = vec![a_record("example.com.", [1, 2, 3, 4])];
        let mut answers = zone.dnskey_rrset();
        answers.push(rrsig_record(zone.zone.clone(), zone.sign(&a)));
        let msg = message(ResponseCode::NoError, answers, vec![]);
        assert!(extract_dnskey_rrset_from_answers(&msg, &zone.zone).is_none());
    }

    #[test]
    fn rrsig_signers_lists_each_signer_once() {
        let zone = TestZone::new("example.com.");
        let mut records = zone.signed(vec![a_record("a.example.com.", [1, 1, 1, 1])]);
        records.extend(zone.signed(vec![a_record("b.example.com.", [2, 2, 2, 2])]));
        assert_eq!(rrsig_signers(&records), std::slice::from_ref(&zone.zone));
        assert_eq!(rrsig_of(&records[1]).input().signer_name, zone.zone);
    }

    // -----------------------------------------------------------------
    // Cache bounds and expiry (E1 point 5)
    // -----------------------------------------------------------------

    #[test]
    fn zone_trust_expires_with_its_ttl() {
        let v = RecursiveDnssecValidator::empty();
        let parent = TestZone::new("example.");
        let child = TestZone::new("sub.example.");
        parent.trust_in(&v);
        // TTL 0: the DS may be used for this validation only.
        let records: Vec<Record> = ds_records(&child.zone, &[child.ds()])
            .into_iter()
            .map(|mut r| {
                r.ttl = 0;
                r
            })
            .collect();
        let rrsig = parent.sign(&records);
        assert_eq!(
            v.record_ds_for_child(&parent.zone, &child.zone, &records, &[rrsig]),
            DnssecVerdict::Secure
        );
        assert!(v.zone(&child.zone).is_none(), "expired trust must vanish");
        assert!(v.zones.get(&child.zone).is_none(), "and its entry with it");
    }

    #[test]
    fn trust_deadline_is_capped() {
        let zone = TestZone::new("example.");
        let records: Vec<Record> = zone
            .dnskey_rrset()
            .into_iter()
            .map(|mut r| {
                r.ttl = u32::MAX;
                r
            })
            .collect();
        let rrsig = zone.sign(&records);
        let deadline = trust_deadline(&records, &rrsig, unix_now());
        // Bounded by the one-hour signature validity, well below MAX_TRUST_TTL.
        assert!(deadline <= Instant::now() + Duration::from_secs(3600));
    }

    #[test]
    fn cache_stays_bounded_and_keeps_the_root() {
        let v = RecursiveDnssecValidator::default().with_max_zones_for_test(3);
        let parent = TestZone::new("com.");
        parent.trust_in(&v);
        for idx in 0..10 {
            let child = name(&format!("unsigned{idx}.com."));
            let nsec = nsec_record(
                &child,
                &name("zzz.com."),
                &[RecordType::NS, RecordType::NSEC],
            );
            v.record_insecure_delegation(&parent.zone, &child, &parent.signed(vec![nsec]));
            assert!(v.zones.len() <= 3, "cache grew to {}", v.zones.len());
        }
        assert!(v.zone(&Name::root()).is_some(), "anchors are never evicted");
    }

    #[test]
    fn clear_keeps_only_the_trust_anchors() {
        let v = RecursiveDnssecValidator::default();
        TestZone::new("example.").trust_in(&v);
        v.clear();
        assert!(v.zone(&name("example.")).is_none());
        // Never "no chain at all", which would fail open.
        assert_eq!(v.zone(&Name::root()).unwrap().ds_in_parent.len(), 2);
    }
}
