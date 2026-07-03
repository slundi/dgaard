use hickory_proto::op::Message;
use hickory_proto::rr::Record;

pub fn render(msg: &Message, short: bool, elapsed_ms: Option<u64>) -> String {
    let mut out = String::new();

    if !short {
        header(&mut out, msg);
    }

    if msg.answers.is_empty() && !short {
        out.push_str(";; (no answer section)\n");
    } else {
        for rr in &msg.answers {
            if short {
                out.push_str(&format!("{}\n", rr.data));
            } else {
                out.push_str(&rr_line(rr));
            }
        }
    }

    if !short {
        section(&mut out, ";; AUTHORITY SECTION:", &msg.authorities);
        section(&mut out, ";; ADDITIONAL SECTION:", &msg.additionals);

        if let Some(ms) = elapsed_ms {
            out.push_str(&format!(
                "\n;; Query time: {ms} ms\n;; MSG SIZE rcvd: {}\n",
                wire_size(msg),
            ));
        }
    }

    out
}

fn header(out: &mut String, msg: &Message) {
    let m = &msg.metadata;
    out.push_str(&format!(
        ";; ->>HEADER<<- opcode: {}, status: {}, id: {}\n",
        m.op_code, m.response_code, m.id,
    ));
    out.push_str(&format!(
        ";; flags:{}{}{}{}{}{}{} ; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n\n",
        if matches!(m.message_type, hickory_proto::op::MessageType::Response) {
            " qr"
        } else {
            ""
        },
        if m.authoritative { " aa" } else { "" },
        if m.truncation { " tc" } else { "" },
        if m.recursion_desired { " rd" } else { "" },
        if m.recursion_available { " ra" } else { "" },
        if m.authentic_data { " ad" } else { "" },
        if m.checking_disabled { " cd" } else { "" },
        msg.queries.len(),
        msg.answers.len(),
        msg.authorities.len(),
        msg.additionals.len(),
    ));

    if !msg.queries.is_empty() {
        out.push_str(";; QUESTION SECTION:\n");
        for q in &msg.queries {
            out.push_str(&format!(
                ";{}\t\t{}\t{}\n",
                q.name(),
                q.query_class(),
                q.query_type()
            ));
        }
        out.push('\n');
    }

    if !msg.answers.is_empty() {
        out.push_str(";; ANSWER SECTION:\n");
    }
}

fn section(out: &mut String, title: &str, records: &[Record]) {
    if records.is_empty() {
        return;
    }
    out.push('\n');
    out.push_str(title);
    out.push('\n');
    for rr in records {
        out.push_str(&rr_line(rr));
    }
}

fn rr_line(rr: &Record) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\n",
        rr.name,
        rr.ttl,
        rr.dns_class,
        rr.record_type(),
        rr.data,
    )
}

fn wire_size(msg: &Message) -> usize {
    msg.to_vec().map(|b| b.len()).unwrap_or(0)
}
