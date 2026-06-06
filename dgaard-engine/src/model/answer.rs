use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_resolver::proto::op::Message;
#[cfg(test)]
use hickory_resolver::proto::op::{MessageType, ResponseCode};
use hickory_resolver::proto::rr::RData;

/// Records extracted from the answer section of an upstream DNS response.
///
/// Used by the scoring engine to:
/// - Check for DNS rebinding (A/AAAA resolving to private IPs)
/// - Detect CNAME cloaking (CNAME chains to blocked domains)
/// - Flag DNS tunneling (oversized TXT records)
/// - Score low-TTL fast-flux infrastructure
#[derive(Debug, Default)]
pub struct InspectedAnswer {
    /// IPv4 addresses from A records.
    pub a_records: Vec<Ipv4Addr>,
    /// IPv6 addresses from AAAA records.
    pub aaaa_records: Vec<Ipv6Addr>,
    /// Raw byte segments from TXT records (one entry per TXT string segment).
    pub txt_records: Vec<Vec<u8>>,
    /// CNAME targets (trailing dot stripped).
    pub cname_targets: Vec<String>,
    /// Minimum TTL across all answer records; `None` if there are no answers.
    pub min_ttl: Option<u32>,
}

impl InspectedAnswer {
    /// Parse the answer section from raw upstream DNS response bytes.
    ///
    /// Returns `None` if `bytes` cannot be decoded as a valid DNS message.
    pub fn from_response(bytes: &[u8]) -> Option<Self> {
        let message = Message::from_vec(bytes).ok()?;
        let mut result = Self::default();

        for record in &message.answers {
            let ttl = record.ttl;
            result.min_ttl = Some(match result.min_ttl {
                Some(current) => current.min(ttl),
                None => ttl,
            });

            match &record.data {
                RData::A(a) => result.a_records.push(a.0),
                RData::AAAA(aaaa) => result.aaaa_records.push(aaaa.0),
                RData::CNAME(cname) => {
                    result
                        .cname_targets
                        .push(cname.0.to_string().trim_end_matches('.').to_string());
                }
                RData::TXT(txt) => {
                    for segment in &txt.txt_data {
                        result.txt_records.push(segment.to_vec());
                    }
                }
                _ => {}
            }
        }

        Some(result)
    }

    /// Returns `true` if no recognized answer records were found.
    pub fn is_empty(&self) -> bool {
        self.a_records.is_empty()
            && self.aaaa_records.is_empty()
            && self.txt_records.is_empty()
            && self.cname_targets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME, TXT};
    use hickory_resolver::proto::rr::{Name, RData, Record};

    use super::*;

    fn build_response(answers: Vec<Record>) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.message_type = MessageType::Response;
        msg.metadata.response_code = ResponseCode::NoError;
        for record in answers {
            msg.add_answer(record);
        }
        msg.to_vec().unwrap()
    }

    fn a_record(domain: &str, ip: Ipv4Addr, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_str(&format!("{domain}.")).unwrap(),
            ttl,
            RData::A(A(ip)),
        )
    }

    fn aaaa_record(domain: &str, ip: Ipv6Addr, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_str(&format!("{domain}.")).unwrap(),
            ttl,
            RData::AAAA(AAAA(ip)),
        )
    }

    fn txt_record(domain: &str, data: &[u8], ttl: u32) -> Record {
        let txt = TXT::new(vec![String::from_utf8_lossy(data).into_owned()]);
        Record::from_rdata(
            Name::from_str(&format!("{domain}.")).unwrap(),
            ttl,
            RData::TXT(txt),
        )
    }

    fn cname_record(domain: &str, target: &str, ttl: u32) -> Record {
        let target_name = Name::from_str(&format!("{target}.")).unwrap();
        Record::from_rdata(
            Name::from_str(&format!("{domain}.")).unwrap(),
            ttl,
            RData::CNAME(CNAME(target_name)),
        )
    }

    #[test]
    fn test_inspect_invalid_bytes() {
        assert!(InspectedAnswer::from_response(&[0x00, 0x01]).is_none());
    }

    #[test]
    fn test_inspect_empty_response() {
        let bytes = build_response(vec![]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();
        assert!(answer.is_empty());
        assert!(answer.min_ttl.is_none());
    }

    #[test]
    fn test_inspect_a_record() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let bytes = build_response(vec![a_record("example.com", ip, 300)]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();

        assert_eq!(answer.a_records, vec![ip]);
        assert!(answer.aaaa_records.is_empty());
        assert_eq!(answer.min_ttl, Some(300));
        assert!(!answer.is_empty());
    }

    #[test]
    fn test_inspect_min_ttl_picks_lowest() {
        let bytes = build_response(vec![
            a_record("example.com", Ipv4Addr::new(1, 1, 1, 1), 100),
            a_record("example.com", Ipv4Addr::new(2, 2, 2, 2), 50),
            a_record("example.com", Ipv4Addr::new(3, 3, 3, 3), 200),
        ]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();

        assert_eq!(answer.a_records.len(), 3);
        assert_eq!(answer.min_ttl, Some(50));
    }

    #[test]
    fn test_inspect_cname_target() {
        let bytes = build_response(vec![cname_record("www.example.com", "example.com", 300)]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();

        assert_eq!(answer.cname_targets.len(), 1);
        assert_eq!(answer.cname_targets[0], "example.com");
    }

    #[test]
    fn test_inspect_txt_record() {
        let data = b"v=spf1 include:example.com ~all";
        let bytes = build_response(vec![txt_record("example.com", data, 3600)]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();

        assert_eq!(answer.txt_records.len(), 1);
        assert_eq!(answer.txt_records[0], data.as_slice());
    }

    #[test]
    fn test_inspect_aaaa_record() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let bytes = build_response(vec![aaaa_record("example.com", ip, 600)]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();

        assert_eq!(answer.aaaa_records, vec![ip]);
        assert!(answer.a_records.is_empty());
        assert_eq!(answer.min_ttl, Some(600));
    }
}
