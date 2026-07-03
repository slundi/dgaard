//! Extended DNS Errors (RFC 8914) — option code 15.
//!
//! Wire format inside the OPT payload:
//!   INFO-CODE  u16 (network order)
//!   EXTRA-TEXT UTF-8 bytes, no trailing NUL, may be empty
//!
//! We do not depend on hickory-proto having a first-class EDGE variant.
//! Instead we probe every option in the message's EDNS block and parse
//! any with code 15 ourselves.

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};

const EDGE_CODE: u16 = 15;

/// Decoded Extended DNS Error record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub info_code: u16,
    pub purpose: &'static str,
    pub extra_text: String,
}

/// Collect all EDGE options from the message's EDNS OPT record.
pub fn extract(msg: &Message) -> Vec<Edge> {
    let Some(edns) = msg.edns.as_ref() else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let edge_code_enum: EdnsCode = EDGE_CODE.into();
    for opt in edns.options().get_all(edge_code_enum) {
        if let EdnsOption::Unknown(_, bytes) = opt
            && let Some(edge) = decode(bytes.as_slice())
        {
            out.push(edge);
        }
    }
    out
}

fn decode(bytes: &[u8]) -> Option<Edge> {
    if bytes.len() < 2 {
        return None;
    }
    let info_code = u16::from_be_bytes([bytes[0], bytes[1]]);
    let extra_text = String::from_utf8_lossy(&bytes[2..]).into_owned();
    Some(Edge {
        info_code,
        purpose: info_code_name(info_code),
        extra_text,
    })
}

/// IANA-registered purpose name for an EDGE info code, best-effort.
pub fn info_code_name(code: u16) -> &'static str {
    match code {
        0 => "Other Error",
        1 => "Unsupported DNSKEY Algorithm",
        2 => "Unsupported DS Digest Type",
        3 => "Stale Answer",
        4 => "Forged Answer",
        5 => "DNSSEC Indeterminate",
        6 => "DNSSEC Bogus",
        7 => "Signature Expired",
        8 => "Signature Not Yet Valid",
        9 => "DNSKEY Missing",
        10 => "RRSIGs Missing",
        11 => "No Zone Key Bit Set",
        12 => "NSEC Missing",
        13 => "Cached Error",
        14 => "Not Ready",
        15 => "Blocked",
        16 => "Censored",
        17 => "Filtered",
        18 => "Prohibited",
        19 => "Stale NXDOMAIN Answer",
        20 => "Not Authoritative",
        21 => "Not Supported",
        22 => "No Reachable Authority",
        23 => "Network Error",
        24 => "Invalid Data",
        25 => "Signature Expired before Valid",
        26 => "Too Early",
        27 => "Unsupported NSEC3 Iterations Value",
        _ => "Unassigned",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_info_code_and_text() {
        let mut bytes = vec![];
        bytes.extend_from_slice(&15u16.to_be_bytes()); // code 15 = Blocked
        bytes.extend_from_slice(b"blocked by policy");
        let edge = decode(&bytes).unwrap();
        assert_eq!(edge.info_code, 15);
        assert_eq!(edge.purpose, "Blocked");
        assert_eq!(edge.extra_text, "blocked by policy");
    }

    #[test]
    fn tolerates_missing_text() {
        let bytes = 6u16.to_be_bytes();
        let edge = decode(&bytes).unwrap();
        assert_eq!(edge.info_code, 6);
        assert_eq!(edge.purpose, "DNSSEC Bogus");
        assert!(edge.extra_text.is_empty());
    }

    #[test]
    fn rejects_short_payload() {
        assert!(decode(&[0u8]).is_none());
    }
}
