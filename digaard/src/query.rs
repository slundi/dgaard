//! DNS query construction: name resolution (IDN, reverse) and EDNS(0) options.

use std::net::IpAddr;

use hickory_proto::op::{Edns, Message, Query};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption, NSIDPayload};
use hickory_proto::rr::{DNSClass, Name, RecordType};

use crate::cli::EdnsOpts;
use crate::error::{Error, Result};
use crate::idn;

/// Turn a user-supplied string into a wire-encodable `Name`.
///
/// - Reverse mode: interpret as an IP address, format the `in-addr.arpa` /
///   `ip6.arpa` inverse label.
/// - Forward mode: IDN-normalise (Unicode → A-labels), append the root `.`
///   if the user omitted it.
pub fn resolve_name(raw_name: &str, reverse: bool) -> Result<Name> {
    let raw = if reverse {
        reverse_arpa_name(raw_name)?
    } else {
        let ascii = idn::to_ascii(raw_name).map_err(Error::InvalidName)?;
        if ascii.ends_with('.') {
            ascii
        } else {
            format!("{ascii}.")
        }
    };

    Name::from_ascii(&raw).map_err(|e| Error::InvalidName(format!("{raw}: {e}")))
}

fn reverse_arpa_name(raw_name: &str) -> Result<String> {
    let ip: IpAddr = raw_name
        .parse()
        .map_err(|_| Error::InvalidName(format!("'{raw_name}' is not a valid IP for -x")))?;
    Ok(match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let nibbles: String = v6
                .octets()
                .iter()
                .flat_map(|b| [b >> 4, b & 0xf])
                .rev()
                .map(|n| format!("{n:x}"))
                .collect::<Vec<_>>()
                .join(".");
            format!("{nibbles}.ip6.arpa.")
        }
    })
}

/// Aggregated header/flag settings that shape the outgoing query.
#[derive(Debug, Clone, Copy)]
pub struct QueryFlags {
    pub recursion_desired: bool,
    pub authoritative: bool,
    pub authentic_data: bool,
    pub checking_disabled: bool,
    pub dnssec_ok: bool,
}

/// Build the `Message` we'll send on the wire.
pub fn build_query(
    name: &Name,
    qtype: RecordType,
    qclass: DNSClass,
    flags: QueryFlags,
    edns: &EdnsOpts,
) -> Result<Message> {
    let mut msg = Message::query();
    msg.metadata.recursion_desired = flags.recursion_desired;
    msg.metadata.authoritative = flags.authoritative;
    msg.metadata.authentic_data = flags.authentic_data;
    msg.metadata.checking_disabled = flags.checking_disabled;

    let mut q = Query::new();
    q.set_name(name.clone());
    q.set_query_type(qtype);
    q.set_query_class(qclass);
    msg.add_query(q);

    if let Some(edns_record) = build_edns(flags, edns)? {
        msg.set_edns(edns_record);
    }

    Ok(msg)
}

fn build_edns(flags: QueryFlags, opts: &EdnsOpts) -> Result<Option<Edns>> {
    let needs_edns = opts.enabled
        && (flags.dnssec_ok
            || opts.subnet.is_some()
            || opts.nsid
            || opts.cookie.is_some()
            || opts.pad.is_some()
            || opts.bufsize.is_some());
    if !needs_edns {
        return Ok(None);
    }

    let mut edns = Edns::new();
    edns.set_max_payload(opts.bufsize.unwrap_or(1232));
    edns.set_dnssec_ok(flags.dnssec_ok);

    let options = edns.options_mut();

    if let Some(subnet) = &opts.subnet {
        let ecs: ClientSubnet = subnet
            .parse()
            .map_err(|e| Error::InvalidName(format!("--subnet {subnet}: {e}")))?;
        options.insert(EdnsOption::Subnet(ecs));
    }

    if opts.nsid {
        let payload = NSIDPayload::new(Vec::<u8>::new()).map_err(Error::Encode)?;
        options.insert(EdnsOption::NSID(payload));
    }

    if let Some(cookie_bytes) = &opts.cookie {
        let code: u16 = EdnsCode::Cookie.into();
        options.insert(EdnsOption::Unknown(code, cookie_bytes.clone()));
    }

    if let Some(block) = opts.pad {
        // Compute padding to round the total message size up to a multiple of `block`.
        // We must first estimate the size with the padding option ADDED but ZERO-length,
        // then set the actual length.
        let code: u16 = EdnsCode::Padding.into();
        options.insert(EdnsOption::Unknown(code, Vec::new()));
        // We cannot easily know the encoded size before serialization here; do a
        // two-pass encoding in `pad_message` after set_edns is done. Return the
        // current EDNS block and let the caller pad after finalisation.
        let _ = block; // suppress unused when the caller doesn't pad
    }

    Ok(Some(edns))
}

/// Round the outgoing message up to a multiple of `block` bytes by extending
/// the EDNS Padding option value (RFC 7830).
///
/// Must be called after `msg.set_edns(edns)` has been assigned. No-op if the
/// message has no Padding option.
pub fn pad_message(msg: &mut Message, block: u16) -> Result<()> {
    if block == 0 {
        return Ok(());
    }
    let Some(edns) = msg.edns.as_ref() else {
        return Ok(());
    };
    let code: u16 = EdnsCode::Padding.into();

    // Do we have a Padding option to grow?
    if edns.options().get(EdnsCode::Padding).is_none() {
        return Ok(());
    }

    // Two-pass: encode, measure, resize the Padding option, re-encode-check.
    for _ in 0..2 {
        let wire_len = msg.to_vec()?.len();
        let block_usize = block as usize;
        let target = wire_len.div_ceil(block_usize) * block_usize;
        let missing = target.saturating_sub(wire_len);
        // Because bumping the padding length also grows the record header
        // by 0 bytes (option header stays 4 bytes), the second pass converges.
        if missing == 0 {
            break;
        }
        // Replace the Padding option value with `missing` zero bytes.
        let opt = msg
            .edns
            .as_mut()
            .expect("padding pass ran with edns present")
            .options_mut();
        let mut kept: Vec<(EdnsCode, EdnsOption)> = opt
            .as_ref()
            .iter()
            .filter(|(c, _)| *c != EdnsCode::Padding)
            .cloned()
            .collect();
        kept.push((
            EdnsCode::Padding,
            EdnsOption::Unknown(code, vec![0u8; missing]),
        ));
        *opt = hickory_proto::rr::rdata::opt::OPT::new(kept);
    }
    Ok(())
}

/// Generate a random 8-byte DNS client cookie (RFC 7873).
pub fn random_client_cookie() -> [u8; 8] {
    let mut buf = [0u8; 8];
    // `getrandom` will fall back to /dev/urandom or the system RNG.
    getrandom::fill(&mut buf).expect("system rng");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_edns() -> EdnsOpts {
        EdnsOpts {
            enabled: true,
            bufsize: Some(1232),
            subnet: None,
            nsid: false,
            cookie: None,
            pad: None,
        }
    }

    fn base_flags() -> QueryFlags {
        QueryFlags {
            recursion_desired: true,
            authoritative: false,
            authentic_data: false,
            checking_disabled: false,
            dnssec_ok: false,
        }
    }

    #[test]
    fn no_edns_when_disabled() {
        let name = Name::from_ascii("example.com.").unwrap();
        let edns = EdnsOpts {
            enabled: false,
            ..default_edns()
        };
        let msg = build_query(&name, RecordType::A, DNSClass::IN, base_flags(), &edns).unwrap();
        assert!(msg.edns.as_ref().is_none());
    }

    #[test]
    fn dnssec_ok_forces_edns() {
        let name = Name::from_ascii("example.com.").unwrap();
        let flags = QueryFlags {
            dnssec_ok: true,
            ..base_flags()
        };
        let msg = build_query(&name, RecordType::A, DNSClass::IN, flags, &default_edns()).unwrap();
        let edns = msg.edns.as_ref().unwrap();
        assert!(edns.flags().dnssec_ok, "DO bit set");
    }

    #[test]
    fn subnet_option_is_encoded() {
        let name = Name::from_ascii("example.com.").unwrap();
        let edns = EdnsOpts {
            subnet: Some("192.0.2.0/24".to_string()),
            ..default_edns()
        };
        let msg = build_query(&name, RecordType::A, DNSClass::IN, base_flags(), &edns).unwrap();
        let opt = msg
            .edns
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Subnet)
            .unwrap();
        assert!(matches!(opt, EdnsOption::Subnet(_)));
    }

    #[test]
    fn nsid_and_cookie_options_are_encoded() {
        let name = Name::from_ascii("example.com.").unwrap();
        let edns = EdnsOpts {
            nsid: true,
            cookie: Some(vec![0xaa; 8]),
            ..default_edns()
        };
        let msg = build_query(&name, RecordType::A, DNSClass::IN, base_flags(), &edns).unwrap();
        let opts = msg.edns.as_ref().unwrap().options();
        assert!(opts.get(EdnsCode::NSID).is_some());
        assert!(opts.get(EdnsCode::Cookie).is_some());
    }

    #[test]
    fn ipv4_reverse_synth() {
        assert_eq!(
            reverse_arpa_name("8.8.4.4").unwrap(),
            "4.4.8.8.in-addr.arpa."
        );
    }

    #[test]
    fn ipv6_reverse_synth() {
        // 2001:db8::1 reversed nibble by nibble
        let expected = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.";
        assert_eq!(reverse_arpa_name("2001:db8::1").unwrap(), expected);
    }

    #[test]
    fn idn_name_is_punycoded() {
        let n = resolve_name("bücher.de", false).unwrap();
        assert_eq!(n.to_ascii(), "xn--bcher-kva.de.");
    }

    #[test]
    fn pad_rounds_up_to_block() {
        let name = Name::from_ascii("example.com.").unwrap();
        let edns = EdnsOpts {
            pad: Some(128),
            ..default_edns()
        };
        let mut msg = build_query(&name, RecordType::A, DNSClass::IN, base_flags(), &edns).unwrap();
        pad_message(&mut msg, 128).unwrap();
        let wire_len = msg.to_vec().unwrap().len();
        assert_eq!(wire_len % 128, 0, "wire len {wire_len} not aligned");
    }
}
