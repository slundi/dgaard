use hickory_proto::op::Message;
use hickory_proto::rr::Record;
use serde_json::{Value, json};

pub fn render(msg: &Message, elapsed_ms: Option<u64>, query_label: &str) -> String {
    let m = &msg.metadata;

    let questions: Vec<Value> = msg
        .queries
        .iter()
        .map(|q| {
            json!({
                "name": q.name().to_string(),
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
        "answer":     rr_to_json(&msg.answers),
        "authority":  rr_to_json(&msg.authorities),
        "additional": rr_to_json(&msg.additionals),
    });

    if let Some(ms) = elapsed_ms {
        obj["query_time_ms"] = json!(ms);
    }

    obj.to_string()
}

fn rr_to_json(records: &[Record]) -> Value {
    records
        .iter()
        .map(|rr| {
            json!({
                "name":  rr.name.to_string(),
                "ttl":   rr.ttl,
                "type":  rr.record_type().to_string(),
                "class": rr.dns_class.to_string(),
                "data":  rr.data.to_string(),
            })
        })
        .collect()
}
