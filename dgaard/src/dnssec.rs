//! Forwarder-mode DNSSEC: validate the very answer relayed to the client.
//!
//! The forwarder asks its upstream with DO=1 (send the signatures) and
//! CD=1 (do not filter bogus data, dgaard judges it). The answer bytes are
//! then checked by the same chain validator as recursive mode
//! ([`RecursiveDnssecValidator`]): the DS / DNSKEY rrsets the answer needs
//! are fetched through the upstream, verified from the root trust anchors
//! down, and cached for their TTL. Only cold zones cost extra queries, at
//! most [`MAX_CHAIN_QUERIES`] per answer.
//!
//! Clients that did not ask for DNSSEC records (no DO bit) get the answer
//! without them ([`client_view`]), as RFC 4035 §3.2.1 requires.

use std::io;

use async_trait::async_trait;
use hickory_resolver::proto::op::{Message, ResponseCode};
use hickory_resolver::proto::rr::{Name, RecordType};

use crate::dns::dnssec_chain::{
    DnssecVerdict, RecursiveDnssecValidator, ZoneStatus, extract_dnskey_rrset_from_answers,
    extract_signed_rrset, rrsig_signers,
};

/// Upper bound on DS / DNSKEY queries spent validating one answer.
pub const MAX_CHAIN_QUERIES: u32 = 16;

/// EDNS payload advertised upstream when dgaard adds its own OPT record
/// (DNS Flag Day 2020 value; DNSKEY answers rarely fit in 512 bytes).
const VALIDATING_PAYLOAD: u16 = 1232;

/// Result of the DNSSEC validation of an answer.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DnssecStatus {
    /// Validated (Secure), or nothing to validate (unsigned zone proven
    /// insecure, validation disabled or declined by the client).
    Ok,
    /// DNSSEC validation failed: forged, stripped or expired signatures,
    /// unproven denial or broken chain under a signed zone.
    Bogus,
}

/// True when the client set CD ("checking disabled", RFC 4035 §3.2.2):
/// it validates for itself and wants the data as is.
pub fn client_disabled_checking(query: &Message) -> bool {
    query.metadata.checking_disabled
}

fn client_dnssec_ok(query: &Message) -> bool {
    query
        .edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok)
}

/// The query to forward when dgaard validates: the client's, with DO=1
/// and CD=1. The client's EDNS payload is kept when larger than
/// [`VALIDATING_PAYLOAD`].
pub fn validating_query(query: &Message) -> Message {
    let mut outgoing = query.clone();
    outgoing.metadata.checking_disabled = true;
    let mut edns = query.edns.clone().unwrap_or_default();
    edns.set_max_payload(edns.max_payload().max(VALIDATING_PAYLOAD));
    edns.set_dnssec_ok(true);
    outgoing.set_edns(edns);
    outgoing
}

/// Record types only a DNSSEC-aware client asked for.
fn is_dnssec_type(rtype: RecordType) -> bool {
    matches!(
        rtype,
        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
    )
}

/// Turn the validated upstream answer back into what `client` asked for.
/// Without DO, DNSSEC records (RRSIG, NSEC, NSEC3 — unless they are the
/// queried type) are dropped and the OPT record follows the client's: none
/// when it sent none, DO cleared otherwise. A DO client gets the bytes
/// unchanged. `None` when the answer cannot be re-encoded.
pub fn client_view(response: &[u8], client: &Message) -> Option<Vec<u8>> {
    if client_dnssec_ok(client) {
        return Some(response.to_vec());
    }
    let mut message = Message::from_vec(response).ok()?;
    let qtype = client.queries.first().map(|q| q.query_type());
    let keep = |rtype: RecordType| !is_dnssec_type(rtype) || Some(rtype) == qtype;
    message.answers.retain(|r| keep(r.record_type()));
    message.authorities.retain(|r| keep(r.record_type()));
    message.additionals.retain(|r| keep(r.record_type()));
    match (&client.edns, message.edns.as_mut()) {
        (None, _) => message.edns = None,
        (Some(_), Some(edns)) => {
            edns.set_dnssec_ok(false);
        }
        (Some(_), None) => {}
    }
    message.to_vec().ok()
}

/// Where the chain of trust comes from: DS and DNSKEY lookups. Production
/// asks the configured upstreams ([`UpstreamChain`]); tests serve fixtures.
#[async_trait]
pub trait ChainSource: Send + Sync {
    async fn lookup(&self, name: &Name, rtype: RecordType) -> io::Result<Message>;
}

/// [`ChainSource`] over the forwarder's upstream servers, with DO+CD and
/// TCP retry for truncated answers (DNSKEY rrsets are large).
pub struct UpstreamChain;

#[async_trait]
impl ChainSource for UpstreamChain {
    async fn lookup(&self, name: &Name, rtype: RecordType) -> io::Result<Message> {
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(hickory_resolver::proto::op::Query::query(
            name.clone(),
            rtype,
        ));
        let bytes = validating_query(&query)
            .to_vec()
            .map_err(|e| io::Error::other(format!("encode chain query: {e}")))?;
        let response = crate::dns::upstream::forward_to_upstream(&bytes, true).await?;
        Message::from_vec(&response).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Builds the chain of trust one answer needs, within a query budget.
struct ChainBuilder<'a> {
    validator: &'a RecursiveDnssecValidator,
    source: &'a dyn ChainSource,
    queries_left: u32,
}

impl ChainBuilder<'_> {
    async fn lookup(&mut self, name: &Name, rtype: RecordType) -> Option<Message> {
        if self.queries_left == 0 {
            return None;
        }
        self.queries_left -= 1;
        self.source.lookup(name, rtype).await.ok()
    }

    /// Fetch and validate `zone`'s DNSKEY rrset when its DS (for the root,
    /// the trust anchors) is known but its keys are not.
    async fn ensure_keys(&mut self, zone: &Name) {
        if !self.validator.needs_keys(zone) {
            return;
        }
        if let Some(response) = self.lookup(zone, RecordType::DNSKEY).await
            && let Some((records, rrsigs)) = extract_dnskey_rrset_from_answers(&response, zone)
        {
            self.validator.record_dnskey_rrset(zone, &records, &rrsigs);
        }
    }

    /// Learn the zone cuts between the root and `target`, shallowest first,
    /// until `target`'s zone is known: each cut gets its DS (verified by the
    /// parent) and DNSKEY, or a proven insecure delegation, after which
    /// nothing below needs a signature. A name that is not a cut leaves no
    /// state and the walk goes deeper.
    async fn walk_to(&mut self, target: &Name) {
        self.ensure_keys(&Name::root()).await;
        if let Some((zone, status)) = self.validator.closest_zone(target)
            && (zone == *target || matches!(status, ZoneStatus::Insecure))
        {
            self.ensure_keys(&zone).await;
            return;
        }

        let mut candidates = Vec::new();
        let mut candidate = target.clone();
        while !candidate.is_root() {
            candidates.push(candidate.clone());
            candidate = candidate.base_name();
        }
        for cut in candidates.into_iter().rev() {
            match self.validator.zone_status(&cut) {
                Some(ZoneStatus::Insecure) => return,
                Some(_) => {
                    self.ensure_keys(&cut).await;
                    continue;
                }
                None => {}
            }
            // Only a signed parent can vouch for (or deny) a child DS.
            let Some((parent, ZoneStatus::Secure(_))) =
                self.validator.closest_zone(&cut.base_name())
            else {
                return;
            };
            let Some(response) = self.lookup(&cut, RecordType::DS).await else {
                return;
            };
            if let Some((ds, rrsigs)) =
                extract_signed_rrset(&response.answers, &cut, RecordType::DS)
            {
                self.validator
                    .record_ds_for_child(&parent, &cut, &ds, &rrsigs);
                self.ensure_keys(&cut).await;
                continue;
            }
            self.validator
                .record_insecure_delegation(&parent, &cut, &response.authorities);
            if self.validator.zone_status(&cut).is_some()
                || response.metadata.response_code == ResponseCode::NXDomain
            {
                return;
            }
        }
    }
}

/// Validate `response` (the answer to `qname` / `qtype`) with `validator`,
/// fetching the chain of trust it needs from `source`.
pub async fn validate_with(
    validator: &RecursiveDnssecValidator,
    source: &dyn ChainSource,
    response: &Message,
    qname: &Name,
    qtype: RecordType,
) -> DnssecVerdict {
    let mut builder = ChainBuilder {
        validator,
        source,
        queries_left: MAX_CHAIN_QUERIES,
    };
    // Signed data: chain every signer. Unsigned data: find the insecure
    // cut that explains it (none under a signed zone means stripped).
    let mut targets = rrsig_signers(&response.answers);
    for signer in rrsig_signers(&response.authorities) {
        if !targets.contains(&signer) {
            targets.push(signer);
        }
    }
    for name in crate::dns::recursive::unsigned_names(response, qname) {
        if !targets.contains(&name) {
            targets.push(name);
        }
    }
    for target in &targets {
        builder.walk_to(target).await;
    }
    validator.validate_message_for(response, qname, qtype)
}

/// Validate the forwarded answer `response` to `qname` / `qtype` against
/// the process-wide validator, the chain coming from the upstreams.
///
/// An unparsable answer is not judged here (it fails elsewhere).
pub async fn validate(response: &[u8], qname: &Name, qtype: RecordType) -> DnssecStatus {
    let Ok(message) = Message::from_vec(response) else {
        return DnssecStatus::Ok;
    };
    match validate_with(
        &crate::RECURSIVE_DNSSEC,
        &UpstreamChain,
        &message,
        qname,
        qtype,
    )
    .await
    {
        DnssecVerdict::Bogus => DnssecStatus::Bogus,
        DnssecVerdict::Secure | DnssecVerdict::Insecure => DnssecStatus::Ok,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use hickory_resolver::proto::op::{Edns, MessageType, Query};
    use hickory_resolver::proto::rr::Record;

    use super::*;
    use crate::dns::dnssec_chain::test_support::{
        TestZone, a_record, ds_records, name, nsec_record,
    };

    fn query(qname: &str, qtype: RecordType) -> Message {
        let mut msg = Message::query();
        msg.add_query(Query::query(name(qname), qtype));
        msg
    }

    fn response(qname: &str, rcode: ResponseCode, answers: Vec<Record>) -> Message {
        let mut msg = query(qname, RecordType::A);
        msg.metadata.message_type = MessageType::Response;
        msg.metadata.response_code = rcode;
        msg.answers = answers;
        msg
    }

    fn answer(records: Vec<Record>) -> Message {
        response(".", ResponseCode::NoError, records)
    }

    fn with_edns(mut msg: Message, payload: u16, dnssec_ok: bool) -> Message {
        let mut edns = Edns::new();
        edns.set_max_payload(payload);
        edns.set_dnssec_ok(dnssec_ok);
        msg.set_edns(edns);
        msg
    }

    // ---- query rewriting ----

    #[test]
    fn validating_query_asks_for_signatures_and_unfiltered_data() {
        let plain = query("www.a.com.", RecordType::A);
        let outgoing = validating_query(&plain);
        assert!(outgoing.metadata.checking_disabled);
        let edns = outgoing.edns.as_ref().expect("OPT added");
        assert!(edns.flags().dnssec_ok);
        assert_eq!(edns.max_payload(), VALIDATING_PAYLOAD);
        assert_eq!(outgoing.queries, plain.queries);

        let big = with_edns(query("www.a.com.", RecordType::A), 4096, false);
        assert_eq!(validating_query(&big).edns.unwrap().max_payload(), 4096);
    }

    #[test]
    fn checking_disabled_is_read_from_the_client_query() {
        let mut msg = query("www.a.com.", RecordType::A);
        assert!(!client_disabled_checking(&msg));
        msg.metadata.checking_disabled = true;
        assert!(client_disabled_checking(&msg));
    }

    // ---- what the client receives ----

    fn signed_response_bytes() -> Vec<u8> {
        let zone = TestZone::new("a.com.");
        let mut msg = response(
            "www.a.com.",
            ResponseCode::NoError,
            zone.signed(vec![a_record("www.a.com.", [192, 0, 2, 1])]),
        );
        msg.authorities = zone.signed(vec![nsec_record(
            &name("a.com."),
            &name("www.a.com."),
            &[RecordType::NS, RecordType::NSEC],
        )]);
        with_edns(msg, 1232, true).to_vec().unwrap()
    }

    fn types_in(bytes: &[u8]) -> Vec<RecordType> {
        let msg = Message::from_vec(bytes).unwrap();
        msg.answers
            .iter()
            .chain(&msg.authorities)
            .map(Record::record_type)
            .collect()
    }

    #[test]
    fn client_without_edns_gets_no_dnssec_records_and_no_opt() {
        let bytes = signed_response_bytes();
        let view = client_view(&bytes, &query("www.a.com.", RecordType::A)).unwrap();
        assert_eq!(types_in(&view), [RecordType::A]);
        assert!(Message::from_vec(&view).unwrap().edns.is_none());
    }

    #[test]
    fn client_with_edns_but_no_do_keeps_opt_without_do() {
        let bytes = signed_response_bytes();
        let client = with_edns(query("www.a.com.", RecordType::A), 1232, false);
        let view = client_view(&bytes, &client).unwrap();
        assert_eq!(types_in(&view), [RecordType::A]);
        let edns = Message::from_vec(&view).unwrap().edns.expect("OPT kept");
        assert!(!edns.flags().dnssec_ok);
    }

    #[test]
    fn dnssec_aware_client_gets_the_answer_unchanged() {
        let bytes = signed_response_bytes();
        let client = with_edns(query("www.a.com.", RecordType::A), 1232, true);
        assert_eq!(client_view(&bytes, &client).unwrap(), bytes);
    }

    #[test]
    fn explicitly_queried_dnssec_types_are_kept() {
        let bytes = signed_response_bytes();
        let view = client_view(&bytes, &query("a.com.", RecordType::NSEC)).unwrap();
        assert_eq!(types_in(&view), [RecordType::A, RecordType::NSEC]);
        assert!(client_view(b"garbage", &query("a.com.", RecordType::A)).is_none());
    }

    // ---- chain validation through a chain source ----

    type Handler = Box<dyn Fn(&Name, RecordType) -> Message + Send + Sync>;

    /// Chain source serving fixtures; counts lookups.
    struct FixtureChain {
        handler: Handler,
        lookups: AtomicU32,
    }

    impl FixtureChain {
        fn new(handler: impl Fn(&Name, RecordType) -> Message + Send + Sync + 'static) -> Self {
            Self {
                handler: Box::new(handler),
                lookups: AtomicU32::new(0),
            }
        }

        fn lookups(&self) -> u32 {
            self.lookups.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ChainSource for FixtureChain {
        async fn lookup(&self, name: &Name, rtype: RecordType) -> io::Result<Message> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            Ok((self.handler)(name, rtype))
        }
    }

    /// `.` → `com.` → `a.com.`, all signed; `b.com.` an insecure
    /// delegation proven by an NSEC. Returns the validator anchored on the
    /// fixture root, the chain source and the `a.com.` zone.
    fn signed_world() -> (RecursiveDnssecValidator, FixtureChain, TestZone) {
        let root = TestZone::new(".");
        let com = TestZone::new("com.");
        let a_com = TestZone::new("a.com.");
        let validator = RecursiveDnssecValidator::with_root_anchors(&[root.as_root_anchor()]);

        let root_keys = root.signed(root.dnskey_rrset());
        let com_ds = root.signed(ds_records(&com.zone, &[com.ds()]));
        let com_keys = com.signed(com.dnskey_rrset());
        let a_ds = com.signed(ds_records(&a_com.zone, &[a_com.ds()]));
        let a_keys = a_com.signed(a_com.dnskey_rrset());
        let b_proof = com.signed(vec![nsec_record(
            &name("b.com."),
            &name("c.com."),
            &[RecordType::NS, RecordType::NSEC],
        )]);
        let source = FixtureChain::new(move |qname, rtype| {
            match (qname.to_string().as_str(), rtype) {
                (".", RecordType::DNSKEY) => answer(root_keys.clone()),
                ("com.", RecordType::DS) => answer(com_ds.clone()),
                ("com.", RecordType::DNSKEY) => answer(com_keys.clone()),
                ("a.com.", RecordType::DS) => answer(a_ds.clone()),
                ("a.com.", RecordType::DNSKEY) => answer(a_keys.clone()),
                ("b.com.", RecordType::DS) => {
                    let mut nodata = answer(Vec::new());
                    nodata.authorities = b_proof.clone();
                    nodata
                }
                // NODATA without proof.
                _ => answer(Vec::new()),
            }
        });
        (validator, source, a_com)
    }

    async fn verdict_of(
        validator: &RecursiveDnssecValidator,
        source: &FixtureChain,
        msg: &Message,
        qname: &str,
    ) -> DnssecVerdict {
        validate_with(validator, source, msg, &name(qname), RecordType::A).await
    }

    #[tokio::test]
    async fn signed_answer_is_secure_and_its_chain_is_cached() {
        let (validator, source, a_com) = signed_world();
        let msg = response(
            "www.a.com.",
            ResponseCode::NoError,
            a_com.signed(vec![a_record("www.a.com.", [192, 0, 2, 1])]),
        );
        assert_eq!(
            verdict_of(&validator, &source, &msg, "www.a.com.").await,
            DnssecVerdict::Secure
        );
        // root DNSKEY, com DS + DNSKEY, a.com DS + DNSKEY.
        assert_eq!(source.lookups(), 5);

        assert_eq!(
            verdict_of(&validator, &source, &msg, "www.a.com.").await,
            DnssecVerdict::Secure
        );
        assert_eq!(source.lookups(), 5, "warm chain: no more upstream traffic");
    }

    #[tokio::test]
    async fn answer_signed_by_another_key_is_bogus() {
        // What a forged answer on the forwarding path looks like: the
        // validated bytes are the relayed bytes.
        let (validator, source, _) = signed_world();
        let forger = TestZone::new("a.com.");
        let msg = response(
            "www.a.com.",
            ResponseCode::NoError,
            forger.signed(vec![a_record("www.a.com.", [6, 6, 6, 6])]),
        );
        assert_eq!(
            verdict_of(&validator, &source, &msg, "www.a.com.").await,
            DnssecVerdict::Bogus
        );
    }

    #[tokio::test]
    async fn stripped_signatures_are_bogus() {
        let (validator, source, _) = signed_world();
        let msg = response(
            "www.a.com.",
            ResponseCode::NoError,
            vec![a_record("www.a.com.", [6, 6, 6, 6])],
        );
        assert_eq!(
            verdict_of(&validator, &source, &msg, "www.a.com.").await,
            DnssecVerdict::Bogus
        );
    }

    #[tokio::test]
    async fn unproven_nxdomain_under_a_signed_zone_is_bogus() {
        let (validator, source, _) = signed_world();
        let msg = response("gone.a.com.", ResponseCode::NXDomain, Vec::new());
        assert_eq!(
            verdict_of(&validator, &source, &msg, "gone.a.com.").await,
            DnssecVerdict::Bogus
        );
    }

    #[tokio::test]
    async fn proven_insecure_delegation_is_insecure() {
        let (validator, source, _) = signed_world();
        let msg = response(
            "www.b.com.",
            ResponseCode::NoError,
            vec![a_record("www.b.com.", [198, 51, 100, 7])],
        );
        assert_eq!(
            verdict_of(&validator, &source, &msg, "www.b.com.").await,
            DnssecVerdict::Insecure
        );
        let before = source.lookups();
        verdict_of(&validator, &source, &msg, "www.b.com.").await;
        assert_eq!(source.lookups(), before, "the insecure cut is cached");
    }

    #[tokio::test]
    async fn root_key_not_matching_the_anchor_is_bogus() {
        let (_, source, a_com) = signed_world();
        let validator =
            RecursiveDnssecValidator::with_root_anchors(&[TestZone::new(".").as_root_anchor()]);
        let msg = response(
            "www.a.com.",
            ResponseCode::NoError,
            a_com.signed(vec![a_record("www.a.com.", [192, 0, 2, 1])]),
        );
        assert_eq!(
            verdict_of(&validator, &source, &msg, "www.a.com.").await,
            DnssecVerdict::Bogus
        );
    }

    #[tokio::test]
    async fn chain_queries_per_answer_are_bounded() {
        // An unsigned name 20 labels below a signed zone: every label
        // would be probed for a DS without the budget.
        let (validator, source, _) = signed_world();
        let deep = format!("{}a.com.", "x.".repeat(20));
        let msg = response(
            &deep,
            ResponseCode::NoError,
            vec![a_record(&deep, [6, 6, 6, 6])],
        );
        let verdict = verdict_of(&validator, &source, &msg, &deep).await;
        assert_eq!(verdict, DnssecVerdict::Bogus);
        assert_eq!(source.lookups(), MAX_CHAIN_QUERIES);
    }

    #[tokio::test]
    async fn failing_chain_source_leaves_signed_data_bogus() {
        struct Down;
        #[async_trait]
        impl ChainSource for Down {
            async fn lookup(&self, _: &Name, _: RecordType) -> io::Result<Message> {
                Err(io::Error::other("upstream down"))
            }
        }
        let root = TestZone::new(".");
        let validator = RecursiveDnssecValidator::with_root_anchors(&[root.as_root_anchor()]);
        let a_com = TestZone::new("a.com.");
        let msg = response(
            "www.a.com.",
            ResponseCode::NoError,
            a_com.signed(vec![a_record("www.a.com.", [192, 0, 2, 1])]),
        );
        let verdict =
            validate_with(&validator, &Down, &msg, &name("www.a.com."), RecordType::A).await;
        assert_eq!(
            verdict,
            DnssecVerdict::Bogus,
            "fail closed under the anchors"
        );
    }

    #[test]
    fn unparsable_answer_is_left_to_the_rest_of_the_pipeline() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let status = rt.block_on(validate(b"\x00", &name("example.com."), RecordType::A));
        assert_eq!(status, DnssecStatus::Ok);
    }
}
