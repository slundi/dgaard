//! Lightweight DNSSEC validation over a single response.
//!
//! This is intentionally narrow: we classify the response we already have,
//! we do not recursively fetch DS/DNSKEY delegations from the root. Per the
//! roadmap, "scope for M6 is validation of the queried name only".
//!
//! Classification rules (in order):
//!   1. `SERVFAIL` from an upstream validator → BOGUS.
//!   2. `AD` bit set on the response (server validated) → SECURE, trusting the
//!      resolver.
//!   3. RRSIG records cover the answer RRSet AND at least one signature
//!      verifies against a matching DNSKEY (either supplied via
//!      `--trust-anchor` or included in the message's ADDITIONAL/ANSWER
//!      section, e.g. from a DNSKEY query) → SECURE (locally verified).
//!   4. RRSIG records present but none verify → BOGUS.
//!   5. No RRSIG records → INSECURE.

use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, RRSIG};
use hickory_proto::dnssec::{PublicKeyBuf, Verifier};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// One of DNSSEC's three status codes plus a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub status: Status,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The response is protected by DNSSEC and validation succeeded.
    Secure,
    /// The response's zone is not signed (or below the DNSSEC islands).
    Insecure,
    /// The response purports to be signed but signatures did not verify.
    Bogus,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Secure => "SECURE",
            Status::Insecure => "INSECURE",
            Status::Bogus => "BOGUS",
        }
    }
}

/// Trust anchor keys used to boot-strap local validation.
#[derive(Debug, Default, Clone)]
pub struct TrustAnchors {
    /// DNSKEYs indexed by their owner name.
    keys: Vec<(Name, DNSKEY)>,
}

impl TrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn add_dnskey(&mut self, owner: Name, key: DNSKEY) {
        self.keys.push((owner, key));
    }

    /// Drain the anchors into an iterator of `(owner, DNSKEY)` pairs.
    pub fn drain(self) -> impl Iterator<Item = (Name, DNSKEY)> {
        self.keys.into_iter()
    }

    /// Return every trust anchor that is a valid signer for `name`
    /// (i.e. anchor owner is `name` itself or an ancestor).
    pub fn covers<'a>(&'a self, name: &'a Name) -> impl Iterator<Item = &'a DNSKEY> + 'a {
        self.keys.iter().filter_map(
            move |(owner, k)| {
                if owner.zone_of(name) { Some(k) } else { None }
            },
        )
    }
}

/// Parse a BIND-style trust-anchor text file.
///
/// Supports lines of the form:
///   `<name> [<ttl>] [IN] DNSKEY <flags> <proto> <alg> <base64...>`
/// Blank lines and lines starting with `;` are ignored.
pub fn parse_trust_anchor_file(text: &str) -> Result<TrustAnchors, String> {
    let mut anchors = TrustAnchors::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let record =
            parse_one_dnskey(line).map_err(|e| format!("trust-anchor line {}: {e}", lineno + 1))?;
        anchors.add_dnskey(record.0, record.1);
    }
    Ok(anchors)
}

fn parse_one_dnskey(line: &str) -> Result<(Name, DNSKEY), String> {
    let mut toks = line.split_whitespace();
    let name_s = toks.next().ok_or("missing owner name")?;
    let name = Name::from_utf8(name_s).map_err(|e| format!("name '{name_s}': {e}"))?;

    // Optional TTL (integer) or class (IN/CH/HS)
    let mut peek = toks.next().ok_or("truncated line")?;
    if peek.parse::<u32>().is_ok() {
        peek = toks.next().ok_or("truncated line after TTL")?;
    }
    if matches!(
        peek.to_ascii_uppercase().as_str(),
        "IN" | "CH" | "HS" | "ANY"
    ) {
        peek = toks.next().ok_or("truncated line after class")?;
    }
    if !peek.eq_ignore_ascii_case("DNSKEY") {
        return Err(format!("expected DNSKEY, got '{peek}'"));
    }

    let flags: u16 = toks
        .next()
        .ok_or("missing flags")?
        .parse()
        .map_err(|e| format!("flags: {e}"))?;
    let proto: u8 = toks
        .next()
        .ok_or("missing proto")?
        .parse()
        .map_err(|e| format!("proto: {e}"))?;
    if proto != 3 {
        return Err(format!("DNSKEY proto must be 3, got {proto}"));
    }
    let alg_num: u8 = toks
        .next()
        .ok_or("missing algorithm")?
        .parse()
        .map_err(|e| format!("algorithm: {e}"))?;
    let algorithm = hickory_proto::dnssec::Algorithm::from_u8(alg_num);

    // The remainder is base64 public key material, possibly split across tokens.
    let key_b64: String = toks.collect::<Vec<_>>().join("");
    if key_b64.is_empty() {
        return Err("missing public key material".to_string());
    }
    let key_bytes = decode_base64(&key_b64).map_err(|e| format!("public key: {e}"))?;
    let public_key = PublicKeyBuf::new(key_bytes, algorithm);
    let dnskey = DNSKEY::with_flags(flags, public_key);
    Ok((name, dnskey))
}

fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    // Minimal RFC 4648 base64 decoder (padded). Rejects invalid characters.
    const T: [i8; 256] = build_table();
    const fn build_table() -> [i8; 256] {
        let mut t = [-1i8; 256];
        let mut i = 0;
        while i < 26 {
            t[b'A' as usize + i] = i as i8;
            t[b'a' as usize + i] = (i + 26) as i8;
            i += 1;
        }
        let mut i = 0;
        while i < 10 {
            t[b'0' as usize + i] = (i + 52) as i8;
            i += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    }

    let filtered: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    let mut out = Vec::with_capacity(filtered.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for b in filtered {
        let v = T[b as usize];
        if v < 0 {
            return Err(format!("invalid base64 char '{}'", b as char));
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Classify a DNS response according to the rules at the top of this file.
///
/// `anchors` may be empty; in that case only rules 1, 2, 4, 5 apply (rule 3
/// requires a DNSKEY to verify against).
pub fn classify(msg: &Message, anchors: &TrustAnchors) -> Verdict {
    // Rule 1: SERVFAIL.
    if msg.metadata.response_code == ResponseCode::ServFail {
        return Verdict {
            status: Status::Bogus,
            reason: "response code is SERVFAIL".to_string(),
        };
    }

    // Rule 2: AD bit set — trust the validating resolver.
    if msg.metadata.authentic_data {
        return Verdict {
            status: Status::Secure,
            reason: "AD bit set by upstream validating resolver".to_string(),
        };
    }

    // Rule 5 short-circuit: no RRSIG anywhere → INSECURE.
    let mut sigs: Vec<(Name, &RRSIG)> = Vec::new();
    for section in [&msg.answers, &msg.authorities] {
        for rr in section {
            if let RData::DNSSEC(DNSSECRData::RRSIG(ref sig)) = rr.data {
                sigs.push((rr.name.clone(), sig));
            }
        }
    }
    if sigs.is_empty() {
        return Verdict {
            status: Status::Insecure,
            reason: "no RRSIG records in response and AD bit not set".to_string(),
        };
    }

    // Try each RRSIG against every candidate DNSKEY.
    let candidate_keys: Vec<(Name, DNSKEY)> = collect_candidate_keys(msg, anchors);
    if candidate_keys.is_empty() {
        return Verdict {
            status: Status::Bogus,
            reason: "RRSIG present but no DNSKEY or trust anchor to verify against".to_string(),
        };
    }

    let question = match msg.queries.first() {
        Some(q) => q,
        None => {
            return Verdict {
                status: Status::Bogus,
                reason: "response has no question section".to_string(),
            };
        }
    };

    let qtype = question.query_type();
    let qname = question.name().clone();
    let qclass = question.query_class();

    // Records covered by RRSIG must match the RRSIG's type_covered.
    let covered: Vec<&Record> = msg
        .answers
        .iter()
        .filter(|r| r.record_type() == qtype && r.name == qname)
        .collect();
    if covered.is_empty() {
        return Verdict {
            status: Status::Insecure,
            reason: "no records match the question (possibly NODATA / NXDOMAIN)".to_string(),
        };
    }

    for (sig_owner, sig) in &sigs {
        if sig_owner != &qname || sig.input().type_covered != qtype {
            continue;
        }
        for (key_owner, key) in &candidate_keys {
            if !key_owner.zone_of(&qname) {
                continue;
            }
            let ok = key
                .verify_rrsig(&qname, qclass, sig, covered.iter().copied())
                .is_ok();
            if ok {
                return Verdict {
                    status: Status::Secure,
                    reason: format!("locally verified RRSIG against DNSKEY at {key_owner}"),
                };
            }
        }
    }

    Verdict {
        status: Status::Bogus,
        reason: "no RRSIG could be verified with the available DNSKEYs".to_string(),
    }
}

fn collect_candidate_keys(msg: &Message, anchors: &TrustAnchors) -> Vec<(Name, DNSKEY)> {
    let mut keys: Vec<(Name, DNSKEY)> = Vec::new();
    // Any DNSKEYs echoed by the server (e.g. from a DNSKEY query response).
    for section in [&msg.answers, &msg.authorities, &msg.additionals] {
        for rr in section {
            if rr.record_type() == RecordType::DNSKEY
                && let RData::DNSSEC(DNSSECRData::DNSKEY(ref k)) = rr.data
            {
                keys.push((rr.name.clone(), k.clone()));
            }
        }
    }
    // Trust anchors.
    for (name, k) in &anchors.keys {
        keys.push((name.clone(), k.clone()));
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::MessageType;
    use hickory_proto::rr::DNSClass;
    use hickory_proto::rr::rdata::A;
    use std::net::Ipv4Addr;

    fn make_response(name: &str) -> Message {
        let mut m = Message::query();
        m.metadata.message_type = MessageType::Response;
        m.metadata.response_code = ResponseCode::NoError;
        let n = Name::from_ascii(name).unwrap();
        let mut q = hickory_proto::op::Query::new();
        q.set_name(n.clone());
        q.set_query_type(RecordType::A);
        q.set_query_class(DNSClass::IN);
        m.add_query(q);
        m.add_answer(Record::from_rdata(
            n,
            60,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 1))),
        ));
        m
    }

    #[test]
    fn servfail_is_bogus() {
        let mut m = make_response("s.test.");
        m.metadata.response_code = ResponseCode::ServFail;
        let v = classify(&m, &TrustAnchors::new());
        assert_eq!(v.status, Status::Bogus);
        assert!(v.reason.to_lowercase().contains("servfail"));
    }

    #[test]
    fn ad_bit_reports_secure() {
        let mut m = make_response("s.test.");
        m.metadata.authentic_data = true;
        let v = classify(&m, &TrustAnchors::new());
        assert_eq!(v.status, Status::Secure);
        assert!(v.reason.to_lowercase().contains("ad bit"));
    }

    #[test]
    fn no_rrsig_no_ad_is_insecure() {
        let m = make_response("s.test.");
        let v = classify(&m, &TrustAnchors::new());
        assert_eq!(v.status, Status::Insecure);
    }

    #[test]
    fn trust_anchor_parser_accepts_bind_format() {
        let text = "\
            ; sample root KSK\n\
            . 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVBDC+YnzOgWG3z\n\
        ";
        let ta = parse_trust_anchor_file(text).unwrap();
        assert_eq!(ta.keys.len(), 1);
    }

    #[test]
    fn trust_anchor_parser_ignores_blank_and_comment_lines() {
        let text = "; comment\n\n; another\n";
        let ta = parse_trust_anchor_file(text).unwrap();
        assert!(ta.is_empty());
    }

    #[test]
    fn trust_anchor_parser_rejects_bad_algorithm() {
        // Missing key material
        let text = "example. IN DNSKEY 257 3 8\n";
        let err = parse_trust_anchor_file(text).unwrap_err();
        assert!(err.contains("missing public key"));
    }
}
