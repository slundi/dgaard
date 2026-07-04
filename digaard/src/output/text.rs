use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::Record;

use super::Rendered;
use super::color::{ColorMode, Palette};
use super::edge;
use crate::geoip::{CountryFormat, GeoIpDb};
use crate::idn;

pub fn render(
    item: &Rendered<'_>,
    short: bool,
    color: ColorMode,
    edge: bool,
    geoip: Option<&GeoIpDb>,
    country_format: CountryFormat,
) -> String {
    let msg = item.response;
    let palette = color.resolved();
    let mut out = String::new();

    if !short {
        header(&mut out, msg, &palette);
    }

    if msg.answers.is_empty() && !short {
        out.push_str(&format!(
            "{}; (no answer section){}\n",
            palette.comment, palette.reset,
        ));
    } else {
        for rr in &msg.answers {
            if short {
                let country = country_hint(rr, geoip, country_format);
                if country.is_empty() {
                    out.push_str(&format!("{}\n", rr.data));
                } else {
                    out.push_str(&format!(
                        "{} {} {}{}\n",
                        rr.data, palette.comment, country, palette.reset
                    ));
                }
            } else {
                out.push_str(&rr_line(rr, &palette, geoip, country_format));
            }
        }
    }

    if !short {
        section(
            &mut out,
            ";; AUTHORITY SECTION:",
            &msg.authorities,
            &palette,
            None,
            country_format,
        );
        section(
            &mut out,
            ";; ADDITIONAL SECTION:",
            &msg.additionals,
            &palette,
            None,
            country_format,
        );

        if edge {
            let edes = edge::extract(msg);
            if !edes.is_empty() {
                out.push('\n');
                out.push_str(&format!(
                    "{}{}{}\n",
                    palette.header, ";; EDGE (RFC 8914):", palette.reset,
                ));
                for e in edes {
                    if e.extra_text.is_empty() {
                        out.push_str(&format!("; {} (code {})\n", e.purpose, e.info_code,));
                    } else {
                        out.push_str(&format!(
                            "; {} (code {}): {}\n",
                            e.purpose, e.info_code, e.extra_text,
                        ));
                    }
                }
            }
        }

        if let Some(v) = item.verdict {
            out.push('\n');
            let style = match v.status {
                crate::dnssec::Status::Secure => palette.header,
                crate::dnssec::Status::Bogus => palette.error,
                crate::dnssec::Status::Insecure => palette.comment,
            };
            out.push_str(&format!(
                "{s};; DNSSEC: {status} — {reason}{r}\n",
                s = style,
                status = v.status.as_str(),
                reason = v.reason,
                r = palette.reset,
            ));
        }

        if let Some(ms) = item.elapsed_ms {
            out.push_str(&format!(
                "\n{c};; Query time: {ms} ms{r}\n{c};; MSG SIZE rcvd: {sz}{r}\n",
                c = palette.comment,
                r = palette.reset,
                sz = wire_size(msg),
            ));
        }
    }

    out
}

fn header(out: &mut String, msg: &Message, p: &Palette) {
    let m = &msg.metadata;
    let status_style = if m.response_code == ResponseCode::NoError {
        p.header
    } else {
        p.error
    };

    out.push_str(&format!(
        "{h};; ->>HEADER<<-{r} opcode: {op}, status: {sstyle}{st}{r}, id: {id}\n",
        h = p.header,
        r = p.reset,
        op = m.op_code,
        sstyle = status_style,
        st = m.response_code,
        id = m.id,
    ));
    out.push_str(&format!(
        "{c};; flags:{qr}{aa}{tc}{rd}{ra}{ad}{cd} ; QUERY: {q}, ANSWER: {an}, AUTHORITY: {au}, ADDITIONAL: {ad_count}{r}\n\n",
        c = p.comment,
        r = p.reset,
        qr = if matches!(m.message_type, hickory_proto::op::MessageType::Response) {
            " qr"
        } else {
            ""
        },
        aa = if m.authoritative { " aa" } else { "" },
        tc = if m.truncation { " tc" } else { "" },
        rd = if m.recursion_desired { " rd" } else { "" },
        ra = if m.recursion_available { " ra" } else { "" },
        ad = if m.authentic_data { " ad" } else { "" },
        cd = if m.checking_disabled { " cd" } else { "" },
        q = msg.queries.len(),
        an = msg.answers.len(),
        au = msg.authorities.len(),
        ad_count = msg.additionals.len(),
    ));

    if !msg.queries.is_empty() {
        out.push_str(&format!(
            "{h};; QUESTION SECTION:{r}\n",
            h = p.header,
            r = p.reset,
        ));
        for q in &msg.queries {
            let name_str = q.name().to_ascii();
            out.push_str(&format!(
                ";{name}\t\t{cls}{class}{r}\t{ty}{qtype}{r}{unicode}\n",
                name = name_str,
                cls = p.class,
                class = q.query_class(),
                r = p.reset,
                ty = p.rtype,
                qtype = q.query_type(),
                unicode = idn_hint(&name_str, p),
            ));
        }
        out.push('\n');
    }

    if !msg.answers.is_empty() {
        out.push_str(&format!(
            "{h};; ANSWER SECTION:{r}\n",
            h = p.header,
            r = p.reset,
        ));
    }
}

fn section(
    out: &mut String,
    title: &str,
    records: &[Record],
    p: &Palette,
    geoip: Option<&GeoIpDb>,
    country_format: CountryFormat,
) {
    if records.is_empty() {
        return;
    }
    out.push('\n');
    out.push_str(&format!("{}{title}{}\n", p.header, p.reset));
    for rr in records {
        out.push_str(&rr_line(rr, p, geoip, country_format));
    }
}

fn rr_line(
    rr: &Record,
    p: &Palette,
    geoip: Option<&GeoIpDb>,
    country_format: CountryFormat,
) -> String {
    let name_str = rr.name.to_ascii();
    let c = country_hint(rr, geoip, country_format);
    let country_suffix = if c.is_empty() {
        String::new()
    } else {
        format!(" {cmt}; {c}{r}", cmt = p.comment, r = p.reset)
    };
    format!(
        "{n}{name}{r}\t{tl}{ttl}{r}\t{cl}{class}{r}\t{ty}{rtype}{r}\t{data}{unicode}{country}\n",
        n = p.name,
        name = name_str,
        r = p.reset,
        tl = p.ttl,
        ttl = rr.ttl,
        cl = p.class,
        class = rr.dns_class,
        ty = p.rtype,
        rtype = rr.record_type(),
        data = rr.data,
        unicode = idn_hint(&name_str, p),
        country = country_suffix,
    )
}

fn country_hint(rr: &Record, geoip: Option<&GeoIpDb>, fmt: CountryFormat) -> String {
    let db = match geoip {
        Some(db) => db,
        None => return String::new(),
    };
    let data_str = rr.data.to_string();
    let ip: std::net::IpAddr = match data_str.parse() {
        Ok(ip) => ip,
        Err(_) => return String::new(),
    };
    db.lookup_country(ip, fmt).unwrap_or_default()
}

fn idn_hint(name: &str, p: &Palette) -> String {
    if idn::is_idna(name) {
        let uni = idn::to_unicode(name);
        if uni != name {
            return format!(" {c}; ({uni}){r}", c = p.comment, r = p.reset);
        }
    }
    String::new()
}

fn wire_size(msg: &Message) -> usize {
    msg.to_vec().map(|b| b.len()).unwrap_or(0)
}
