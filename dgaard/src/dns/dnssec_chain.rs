//! Recursive-mode DNSSEC chain primitives — Phase 6, session 1.
//!
//! This module owns the building blocks needed by the iterative
//! resolver to validate signatures against a chain of trust rooted at
//! the IANA root KSK:
//!
//! * an embedded **trust anchor** (the root-zone DS records);
//! * a **per-zone DNSKEY cache** populated by the resolver as it walks
//!   the delegation chain;
//! * a **verifier** that uses [`hickory_proto::dnssec::Verifier`] to
//!   check RRSIGs against the cached DNSKEYs;
//! * a **trust hand-off** that bridges parent → child via DS records
//!   signed by the parent's ZSK.
//!
//! ## What lands in **session 1** (this commit)
//!
//! Everything above, plus the integration point — `handle_query` calls
//! [`RecursiveDnssecValidator::validate_message`] on every recursive
//! answer when `[security.dnssec] enabled = true`. Until the resolver
//! actively issues DNSKEY/DS queries (planned for session 2) the cache
//! starts empty, so a response with no cached chain returns
//! [`DnssecVerdict::Insecure`] which the higher layer maps to "fail
//! open / DnssecStatus::Ok" — preserving today's behaviour for users
//! who flip recursive on with DNSSEC enabled.
//!
//! Verified primitives in this commit therefore catch:
//!
//! * RRSIGs whose key the operator pre-seeded (tests, future fixtures);
//! * RRSIGs whose chain *has* been populated by another path (e.g. a
//!   `[security.dnssec] preload_dnskey_path` operator hook — TODO).
//!
//! Verified primitives **do not** yet catch real-world Bogus answers,
//! because we do not yet query DS/DNSKEY upstream during the walk.
//! That's session 2.
//!
//! ## What lands in **session 2**
//!
//! Iterative DNSKEY/DS query plumbing inside
//! [`crate::dns::recursive::RecursiveResolver`]: at every delegation
//! hop, dispatch a parallel DNSKEY query against the new zone and a DS
//! query against the parent; feed both into this validator before
//! continuing the descent.
//!
//! ## What lands in **session 3**
//!
//! NSEC / NSEC3 negative-answer validation and the
//! `verdict == Bogus → SERVFAIL` semantics for `action = "block"`.

use std::sync::Arc;

use dashmap::DashMap;
use hickory_resolver::proto::dnssec::rdata::{DNSKEY, DS, RRSIG};
use hickory_resolver::proto::dnssec::{Algorithm, DigestType, Verifier};
use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record};

/// Outcome of validating a single resource-record set against the
/// in-memory trust state.
///
/// `Secure` and `Bogus` are the cryptographically definitive outcomes.
/// `Insecure` is the **graceful-degradation** state: when we don't have
/// a chain of trust for the zone, we can neither prove the answer
/// genuine nor prove it forged, so the higher layer treats it as a
/// pass (`DnssecStatus::Ok`).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DnssecVerdict {
    /// Signature verified back to the root trust anchor.
    Secure,
    /// No chain available — DNSKEY/DS cache miss for this zone.
    Insecure,
    /// Verification was attempted and failed (bad signature, wrong
    /// algorithm, expired/inception time, key-tag mismatch, …).
    Bogus,
}

// ---------------------------------------------------------------------------
// IANA root trust anchor
// ---------------------------------------------------------------------------

/// Trust anchor pinned at compile time. The recursive validator
/// pre-loads the root zone's authoritative DS rrset from this set, so
/// every chain it later constructs from upstream-fetched DNSKEYs can be
/// verified to terminate at IANA.
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

/// IANA root-zone KSK as published in `root-anchors.xml` — the trust
/// anchor that has been in production since 2017 (a.k.a. "KSK-2017").
///
/// We deliberately ship only this single anchor in session 1. A future
/// commit will land KSK-2024 alongside once we have ground-truth bytes
/// vetted against an IANA-signed `root-anchors.xml` — embedding crypto
/// material without an end-to-end verify is a footgun.
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

const fn hex32(bytes: [u8; 32]) -> [u8; 32] {
    bytes
}

// ---------------------------------------------------------------------------
// Per-zone state cached by the validator
// ---------------------------------------------------------------------------

/// Per-zone state kept by the validator. We store DS records that
/// authenticate the *child* zone's KSK (`ds_in_parent`) alongside the
/// DNSKEYs published by *this* zone (`dnskeys`). Both arrive at
/// different times in a real walk, so we let either be missing.
#[derive(Debug, Default, Clone)]
pub struct ZoneTrustState {
    /// DS records in the parent zone that point to **this** zone's
    /// KSK. Pre-seeded for the root zone from [`ROOT_KSK_2017`].
    pub ds_in_parent: Vec<DS>,
    /// DNSKEYs published at the zone apex. Populated once the resolver
    /// has fetched + verified them against `ds_in_parent`.
    pub dnskeys: Vec<DNSKEY>,
}

impl ZoneTrustState {
    /// Locate a DNSKEY whose key tag matches the RRSIG's `key_tag`.
    /// Two DNSKEYs with the same tag can legitimately coexist (rare
    /// but allowed), so we walk all candidates rather than returning
    /// the first.
    pub fn candidates_for_key_tag(&self, key_tag: u16) -> impl Iterator<Item = &DNSKEY> {
        self.dnskeys.iter().filter(move |dnskey| {
            // Key-tag mismatch isn't fatal — the RRSIG could match a
            // different key with a colliding tag — but it's the
            // primary index. `calculate_key_tag` allocates internally,
            // so we cache nothing and accept the per-verify cost in
            // exchange for a small, audit-friendly footprint.
            dnskey
                .calculate_key_tag()
                .map(|t| t == key_tag)
                .unwrap_or(false)
        })
    }
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
}

impl Default for RecursiveDnssecValidator {
    fn default() -> Self {
        Self::with_root_anchor(ROOT_KSK_2017)
    }
}

impl RecursiveDnssecValidator {
    /// Construct a validator seeded with the IANA root trust anchor as
    /// the *parent DS* of the root zone. Subsequent walks fill in
    /// DNSKEYs as the resolver discovers them.
    pub fn with_root_anchor(anchor: RootTrustAnchor) -> Self {
        let zones = DashMap::new();
        zones.insert(
            Name::root(),
            ZoneTrustState {
                ds_in_parent: vec![DS::new(
                    anchor.key_tag,
                    anchor.algorithm,
                    anchor.digest_type,
                    anchor.digest.to_vec(),
                )],
                dnskeys: Vec::new(),
            },
        );
        Self {
            zones: Arc::new(zones),
        }
    }

    /// Construct with no anchor (useful in tests that exercise the
    /// validator in isolation). Real deployments must use
    /// [`Self::with_root_anchor`] or [`Self::default`].
    #[cfg(test)]
    pub fn empty() -> Self {
        Self {
            zones: Arc::new(DashMap::new()),
        }
    }

    /// Read access to a zone's cached state. Returns `None` when the
    /// zone is unknown. Mostly used by tests; production code should
    /// go through the higher-level `validate_*` methods.
    pub fn zone(&self, zone: &Name) -> Option<ZoneTrustState> {
        self.zones.get(zone).map(|e| e.clone())
    }

    /// Wipe every cached zone. Phase 4 calls `clear()` on the popularity
    /// tracker on blocklist reload; we expose the same primitive here
    /// so an operator hot-reload of trust anchors can drop the chain.
    pub fn clear(&self) {
        self.zones.clear();
    }

    /// Record a DS rrset published by `parent_zone` that claims to
    /// authenticate `child_zone`'s KSK. Returns
    /// [`DnssecVerdict::Secure`] when the parent's signature over the
    /// DS rrset verifies, [`DnssecVerdict::Bogus`] when it fails, and
    /// [`DnssecVerdict::Insecure`] when the parent has no known DNSKEY
    /// (we accept the DS but cannot yet authenticate it; callers may
    /// retry once the parent's DNSKEYs arrive).
    ///
    /// **Invariant the caller must uphold**: the `records` slice must
    /// contain only `RData::DS` rdata for `child_zone`. The validator
    /// does not re-classify rdata kinds.
    pub fn record_ds_for_child(
        &self,
        parent_zone: &Name,
        child_zone: &Name,
        records: &[Record],
        rrsig: &RRSIG,
    ) -> DnssecVerdict {
        // Verify the DS rrset's RRSIG against a DNSKEY in the parent.
        let verdict = self.verify_rrset(parent_zone, child_zone, DNSClass::IN, rrsig, records);
        if verdict == DnssecVerdict::Bogus {
            return verdict;
        }

        let mut ds_values = Vec::with_capacity(records.len());
        for r in records {
            if let RData::DNSSEC(hickory_resolver::proto::dnssec::rdata::DNSSECRData::DS(ds)) =
                &r.data
            {
                ds_values.push(ds.clone());
            }
        }
        if ds_values.is_empty() {
            return DnssecVerdict::Bogus;
        }

        self.zones
            .entry(child_zone.clone())
            .or_default()
            .ds_in_parent = ds_values;
        verdict
    }

    /// Record a DNSKEY rrset for `zone`. The signature on the rrset
    /// must be valid under one of the zone's DNSKEYs *and* the DS
    /// pre-recorded for the zone must cover one of the newly-supplied
    /// keys — otherwise the chain breaks here and we return Bogus.
    pub fn record_dnskey_rrset(
        &self,
        zone: &Name,
        records: &[Record],
        rrsig: &RRSIG,
    ) -> DnssecVerdict {
        // 1. Collect the DNSKEY rdata. The rrset's RRSIG must be
        //    self-signed by one of them (typically the KSK), and that
        //    KSK must match a DS pre-recorded for the zone.
        let mut new_dnskeys: Vec<DNSKEY> = Vec::with_capacity(records.len());
        for r in records {
            if let RData::DNSSEC(hickory_resolver::proto::dnssec::rdata::DNSSECRData::DNSKEY(
                dnskey,
            )) = &r.data
            {
                new_dnskeys.push(dnskey.clone());
            }
        }
        if new_dnskeys.is_empty() {
            return DnssecVerdict::Bogus;
        }

        // 2. Find a KSK candidate covered by the parent DS.
        let zone_entry = self.zones.entry(zone.clone()).or_default();
        if zone_entry.ds_in_parent.is_empty() {
            // No DS yet — we can't authenticate this DNSKEY rrset.
            // Stash it pending DS arrival? No: that would let an
            // attacker pre-poison the cache. Drop and return
            // Insecure; the caller should retry once the DS lands.
            return DnssecVerdict::Insecure;
        }
        let mut ksk_match: Option<&DNSKEY> = None;
        for ds in &zone_entry.ds_in_parent {
            for dnskey in &new_dnskeys {
                if let Ok(true) = ds.covers(zone, dnskey) {
                    ksk_match = Some(dnskey);
                    break;
                }
            }
            if ksk_match.is_some() {
                break;
            }
        }
        let Some(ksk) = ksk_match else {
            return DnssecVerdict::Bogus;
        };

        // 3. Verify the DNSKEY rrset's RRSIG with the matched KSK.
        if verify_with_dnskey(ksk, zone, DNSClass::IN, rrsig, records).is_err() {
            return DnssecVerdict::Bogus;
        }

        // 4. Cache and report Secure. Drop the parent's borrow before
        //    we mutate.
        drop(zone_entry);
        self.zones.entry(zone.clone()).or_default().dnskeys = new_dnskeys;
        DnssecVerdict::Secure
    }

    /// Verify `records` against the cached DNSKEYs of `zone`.
    ///
    /// * Returns `Secure` if one of the candidate DNSKEYs validates.
    /// * Returns `Insecure` if no chain exists yet (zone not cached, or
    ///   cached but no matching key tag).
    /// * Returns `Bogus` if a candidate key was found but verification
    ///   failed — we *did* attempt and we *did* see it fail.
    pub fn verify_rrset(
        &self,
        zone: &Name,
        owner: &Name,
        dns_class: DNSClass,
        rrsig: &RRSIG,
        records: &[Record],
    ) -> DnssecVerdict {
        let Some(zone_entry) = self.zones.get(zone) else {
            return DnssecVerdict::Insecure;
        };
        if zone_entry.dnskeys.is_empty() {
            return DnssecVerdict::Insecure;
        }

        let mut tried_any = false;
        for candidate in zone_entry.candidates_for_key_tag(rrsig.input().key_tag) {
            tried_any = true;
            if candidate
                .verify_rrsig(owner, dns_class, rrsig, records.iter())
                .is_ok()
            {
                return DnssecVerdict::Secure;
            }
        }
        if tried_any {
            DnssecVerdict::Bogus
        } else {
            // No DNSKEY with the requested key_tag — caller should
            // refresh the DNSKEY rrset and retry. Until that lands we
            // treat the answer as Insecure.
            DnssecVerdict::Insecure
        }
    }

    /// Top-level entry point invoked by `handle_query`. Walks the
    /// `message.answers` looking for RRSIGs paired with their covered
    /// rrset and verifies each pair.
    ///
    /// The first `Bogus` short-circuits — any forged record poisons
    /// the entire response in DNSSEC's "best evidence wins"
    /// semantics. Otherwise the most-secure verdict observed (one of
    /// `Secure > Insecure`) is returned.
    pub fn validate_message(&self, message: &Message) -> DnssecVerdict {
        // Group answers by (name, type) so RRSIG matching is O(n).
        let mut best = DnssecVerdict::Insecure;
        let mut seen_signed = false;

        // Collect rrsigs alongside their covered rrset.
        for sig_record in message.answers.iter() {
            let Some(rrsig) = extract_rrsig(sig_record) else {
                continue;
            };
            let covered_type = rrsig.input().type_covered;
            let covered: Vec<&Record> = message
                .answers
                .iter()
                .filter(|r| r.name == sig_record.name && r.record_type() == covered_type)
                .collect();
            if covered.is_empty() {
                // An RRSIG with no covered rrset is malformed.
                return DnssecVerdict::Bogus;
            }
            seen_signed = true;
            let owned: Vec<Record> = covered.into_iter().cloned().collect();
            let zone = rrsig.input().signer_name.clone();
            let verdict =
                self.verify_rrset(&zone, &sig_record.name, sig_record.dns_class, rrsig, &owned);
            match verdict {
                DnssecVerdict::Bogus => return DnssecVerdict::Bogus,
                DnssecVerdict::Secure => best = DnssecVerdict::Secure,
                DnssecVerdict::Insecure => {}
            }
        }

        if !seen_signed {
            // No RRSIG in the answer: zone is either unsigned or the
            // upstream stripped them. Treat as Insecure (fail open).
            return DnssecVerdict::Insecure;
        }
        best
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pull the RRSIG rdata out of a record, if any.
fn extract_rrsig(record: &Record) -> Option<&RRSIG> {
    match &record.data {
        RData::DNSSEC(hickory_resolver::proto::dnssec::rdata::DNSSECRData::RRSIG(rrsig)) => {
            Some(rrsig)
        }
        _ => None,
    }
}

/// Wrap `Verifier::verify_rrsig` with the standard error coercion the
/// rest of the module uses. Pulled out so tests can call it directly.
pub fn verify_with_dnskey(
    dnskey: &DNSKEY,
    name: &Name,
    dns_class: DNSClass,
    rrsig: &RRSIG,
    records: &[Record],
) -> Result<(), &'static str> {
    dnskey
        .verify_rrsig(name, dns_class, rrsig, records.iter())
        .map_err(|_| "rrsig verification failed")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hickory_resolver::proto::dnssec::PublicKeyBuf;
    use hickory_resolver::proto::dnssec::SigningKey;
    use hickory_resolver::proto::dnssec::crypto::EcdsaSigningKey;
    use hickory_resolver::proto::dnssec::rdata::{DNSKEY, RRSIG};
    use hickory_resolver::proto::dnssec::{DnssecSigner, rdata::DNSSECRData};
    use hickory_resolver::proto::rr::rdata::A;
    use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
    use time::OffsetDateTime;

    use super::*;

    /// Build a self-contained zone fixture:
    /// * generate an ECDSA P-256 KSK,
    /// * publish a single matching DNSKEY rrset,
    /// * sign a one-record A rrset under it.
    ///
    /// Returns `(zone, dnskey_rrset, dnskey_rrsig, a_rrset, a_rrsig)`.
    /// All RRSIGs are valid for one hour around `now`.
    fn build_test_zone(
        zone_label: &str,
        a_name: &str,
    ) -> (Name, Vec<Record>, RRSIG, Vec<Record>, RRSIG, DnssecSigner) {
        let zone = Name::parse(zone_label, Some(&Name::root())).unwrap();
        let owner = Name::parse(a_name, Some(&Name::root())).unwrap();

        let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
        let key = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).unwrap();
        let public: PublicKeyBuf = key.to_public_key().unwrap();
        // Flags 257 = ZONE_KEY | SEP — i.e. KSK, which is both zone-key
        // and the secure-entry-point that the DS in the parent points
        // to. Using one key as both KSK and ZSK keeps the test fixture
        // small.
        let dnskey = DNSKEY::with_flags(257, public);

        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            zone.clone(),
            Duration::from_secs(3600),
        );

        // DNSKEY rrset signed by itself.
        let mut dnskey_set = RecordSet::new(zone.clone(), RecordType::DNSKEY, 3600);
        dnskey_set.add_rdata(RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())));
        let now = OffsetDateTime::now_utc();
        let dnskey_rrsig = RRSIG::from_rrset(&dnskey_set, DNSClass::IN, now, &signer).unwrap();
        let dnskey_records: Vec<Record> = dnskey_set.records_without_rrsigs().cloned().collect();

        // A rrset signed by the same key.
        let mut a_set = RecordSet::new(owner.clone(), RecordType::A, 300);
        a_set.add_rdata(RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))));
        let a_rrsig = RRSIG::from_rrset(&a_set, DNSClass::IN, now, &signer).unwrap();
        let a_records: Vec<Record> = a_set.records_without_rrsigs().cloned().collect();

        (
            zone,
            dnskey_records,
            dnskey_rrsig,
            a_records,
            a_rrsig,
            signer,
        )
    }

    #[test]
    fn empty_validator_returns_insecure_for_unknown_zone() {
        // Verifier with no zone cache must fail open (Insecure), not
        // Bogus — DNSSEC's "absence of proof is not proof of absence".
        let v = RecursiveDnssecValidator::empty();
        let zone = Name::parse("example.com", Some(&Name::root())).unwrap();
        let owner = zone.clone();
        let (_, _, _, a_records, a_rrsig, _) = build_test_zone("example.com", "example.com");
        assert_eq!(
            v.verify_rrset(&zone, &owner, DNSClass::IN, &a_rrsig, &a_records),
            DnssecVerdict::Insecure
        );
    }

    #[test]
    fn preseeded_dnskey_yields_secure_verdict() {
        // Round-trip: install a known DNSKEY for the zone directly into
        // the cache, then verify a signed rrset. Confirms our
        // `Verifier`-based primitive matches hickory's own signing.
        let v = RecursiveDnssecValidator::empty();
        let (zone, dnskey_records, _, a_records, a_rrsig, signer) =
            build_test_zone("example.com", "example.com");

        v.zones.insert(
            zone.clone(),
            ZoneTrustState {
                ds_in_parent: Vec::new(),
                dnskeys: dnskey_records
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => Some(dnskey.clone()),
                        _ => None,
                    })
                    .collect(),
            },
        );

        let verdict = v.verify_rrset(&zone, &zone, DNSClass::IN, &a_rrsig, &a_records);
        assert_eq!(
            verdict,
            DnssecVerdict::Secure,
            "signer = {:?}",
            signer.signer_name()
        );
    }

    #[test]
    fn tampered_record_is_bogus() {
        // Pre-seed a DNSKEY, then verify against a *modified* rrset.
        // Hickory's verifier must reject the bad TBS hash.
        let v = RecursiveDnssecValidator::empty();
        let (zone, dnskey_records, _, a_records, a_rrsig, _) =
            build_test_zone("example.com", "example.com");
        v.zones.insert(
            zone.clone(),
            ZoneTrustState {
                ds_in_parent: Vec::new(),
                dnskeys: dnskey_records
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => Some(dnskey.clone()),
                        _ => None,
                    })
                    .collect(),
            },
        );

        // Tamper: replace the A record's payload with a different IP.
        let mut tampered = a_records.clone();
        tampered[0].data = RData::A(A(std::net::Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!(
            v.verify_rrset(&zone, &zone, DNSClass::IN, &a_rrsig, &tampered),
            DnssecVerdict::Bogus
        );
    }

    #[test]
    fn record_dnskey_rrset_requires_parent_ds_match() {
        // No DS pre-seeded → record_dnskey_rrset returns Insecure
        // (we can't authenticate the new keys yet).
        let v = RecursiveDnssecValidator::empty();
        let (zone, dnskey_records, dnskey_rrsig, _, _, _) =
            build_test_zone("example.com", "example.com");
        let verdict = v.record_dnskey_rrset(&zone, &dnskey_records, &dnskey_rrsig);
        assert_eq!(verdict, DnssecVerdict::Insecure);
    }

    #[test]
    fn record_dnskey_rrset_secures_when_ds_matches() {
        // Seed the parent DS by computing it from the test KSK, then
        // observe Secure once we record the matching DNSKEY rrset.
        let v = RecursiveDnssecValidator::empty();
        let (zone, dnskey_records, dnskey_rrsig, _, _, _) =
            build_test_zone("example.com", "example.com");

        let dnskey = match &dnskey_records[0].data {
            RData::DNSSEC(DNSSECRData::DNSKEY(d)) => d.clone(),
            _ => unreachable!(),
        };
        let digest = dnskey.to_digest(&zone, DigestType::SHA256).unwrap();
        let ds = DS::new(
            dnskey.calculate_key_tag().unwrap(),
            dnskey.algorithm(),
            DigestType::SHA256,
            digest.as_ref().to_vec(),
        );

        v.zones.insert(
            zone.clone(),
            ZoneTrustState {
                ds_in_parent: vec![ds],
                dnskeys: Vec::new(),
            },
        );

        assert_eq!(
            v.record_dnskey_rrset(&zone, &dnskey_records, &dnskey_rrsig),
            DnssecVerdict::Secure
        );
        // The DNSKEY is now cached.
        assert!(!v.zone(&zone).unwrap().dnskeys.is_empty());
    }

    #[test]
    fn validate_message_returns_insecure_for_unsigned_response() {
        // No RRSIGs in the response → Insecure, not Bogus. This is the
        // "common case" until the resolver actively pulls DNSKEY/DS
        // (session 2).
        let v = RecursiveDnssecValidator::default();
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            Name::parse("example.com.", None).unwrap(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));
        assert_eq!(v.validate_message(&msg), DnssecVerdict::Insecure);
    }

    #[test]
    fn validate_message_secure_when_signed_with_known_key() {
        // End-to-end: a signed rrset gets correctly classified Secure
        // once we put the DNSKEY in the validator cache.
        let v = RecursiveDnssecValidator::empty();
        let (zone, dnskey_records, _, a_records, a_rrsig, _) =
            build_test_zone("example.com", "example.com");
        v.zones.insert(
            zone.clone(),
            ZoneTrustState {
                ds_in_parent: Vec::new(),
                dnskeys: dnskey_records
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => Some(dnskey.clone()),
                        _ => None,
                    })
                    .collect(),
            },
        );

        let mut msg = Message::query();
        for r in &a_records {
            msg.add_answer(r.clone());
        }
        msg.add_answer(Record::from_rdata(
            zone.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(a_rrsig)),
        ));
        assert_eq!(v.validate_message(&msg), DnssecVerdict::Secure);
    }

    #[test]
    fn root_anchor_seeds_only_the_root_zone() {
        // Sanity: default validator carries the IANA anchor under `.`
        // and nothing else. A bug that pre-seeded sibling zones with
        // the same DS would silently broaden the trust scope.
        let v = RecursiveDnssecValidator::default();
        let root = v.zone(&Name::root()).expect("root must be seeded");
        assert_eq!(root.ds_in_parent.len(), 1);
        assert_eq!(root.ds_in_parent[0].key_tag(), 20326);
        let other = Name::parse("example.com.", None).unwrap();
        assert!(v.zone(&other).is_none());
    }

    #[test]
    fn clear_drops_every_zone_including_root() {
        // Trust anchor reload (future operator hook) must be able to
        // wipe the cache so a re-seeded anchor takes effect.
        let v = RecursiveDnssecValidator::default();
        v.clear();
        assert!(v.zone(&Name::root()).is_none());
    }
}
