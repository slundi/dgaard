use hickory_proto::op::Message;
use hickory_proto::rr::Record;
use serde_json::{Value, json};

use super::edge;
use crate::dnssec::Verdict;
use crate::geoip::{CountryFormat, GeoIpDb};
use crate::idn;

#[allow(clippy::too_many_arguments)]
pub fn render(
    msg: &Message,
    elapsed_ms: Option<u64>,
    query_label: &str,
    edge: bool,
    verdict: Option<&Verdict>,
    geoip: Option<&GeoIpDb>,
    country_format: CountryFormat,
) -> String {
    let m = &msg.metadata;

    let questions: Vec<Value> = msg
        .queries
        .iter()
        .map(|q| {
            let ascii = q.name().to_ascii();
            json!({
                "name": ascii,
                "unicode_name": maybe_unicode(&ascii),
                "type": q.query_type().to_string(),
                "class": q.query_class().to_string(),
            })
        })
        .collect();

    let mut obj = json!({
        "query":      query_label,
        "status":     format!("{}", m.response_code),
        "id":         m.id,
        "flags": {
            "qr": matches!(m.message_type, hickory_proto::op::MessageType::Response),
            "aa": m.authoritative,
            "tc": m.truncation,
            "rd": m.recursion_desired,
            "ra": m.recursion_available,
            "ad": m.authentic_data,
            "cd": m.checking_disabled,
        },
        "question":   questions,
        "answer":     rr_to_json(&msg.answers, geoip, country_format),
        "authority":  rr_to_json(&msg.authorities, None, country_format),
        "additional": rr_to_json(&msg.additionals, None, country_format),
    });

    if edge {
        let edes = edge::extract(msg);
        if !edes.is_empty() {
            obj["edge"] = edes
                .iter()
                .map(|e| {
                    json!({
                        "code": e.info_code,
                        "purpose": e.purpose,
                        "text": e.extra_text,
                    })
                })
                .collect::<Vec<_>>()
                .into();
        }
    }

    if let Some(v) = verdict {
        obj["dnssec"] = json!({
            "status": v.status.as_str(),
            "reason": v.reason,
        });
    }

    if let Some(ms) = elapsed_ms {
        obj["query_time_ms"] = json!(ms);
    }

    obj.to_string()
}

fn rr_to_json(records: &[Record], geoip: Option<&GeoIpDb>, fmt: CountryFormat) -> Value {
    records
        .iter()
        .map(|rr| {
            let ascii = rr.name.to_ascii();
            let data = rr.data.to_string();
            let country: Option<String> = geoip.and_then(|db| {
                data.parse::<std::net::IpAddr>()
                    .ok()
                    .and_then(|ip| db.lookup_country(ip, fmt))
            });
            let mut obj = json!({
                "name":         ascii,
                "unicode_name": maybe_unicode(&ascii),
                "ttl":          rr.ttl,
                "type":         rr.record_type().to_string(),
                "class":        rr.dns_class.to_string(),
                "data":         data,
            });
            if let Some(c) = country {
                obj["country"] = json!(c);
            }
            obj
        })
        .collect()
}

fn maybe_unicode(name: &str) -> Option<String> {
    if idn::is_idna(name) {
        let uni = idn::to_unicode(name);
        if uni != name {
            return Some(uni);
        }
    }
    None
}
