mod cli;
mod error;
mod output;
mod transport;

use std::time::Instant;

use hickory_proto::op::{Edns, Message, Query};
use hickory_proto::rr::{Name, RecordType};

use error::{Error, Result};
use transport::{TransportConfig, TransportKind};

#[tokio::main]
async fn main() {
    env_logger::init();

    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = cli::parse();

    let name = resolve_name(&args)?;
    let qtype = if args.reverse {
        RecordType::PTR
    } else {
        args.qtype
    };

    let server = args.server.as_deref().unwrap_or("8.8.8.8").to_owned();
    let port = args.port.unwrap_or_else(|| args.transport.default_port());

    let cfg = TransportConfig {
        server,
        port,
        timeout_ms: args.timeout_ms,
        ipv4_only: args.ipv4,
        ipv6_only: args.ipv6,
    };

    let query = build_query(&name, qtype, &args);
    let mut kind = args.transport;

    let start = Instant::now();
    let response = match transport::send(kind, &cfg, &query).await {
        Ok(msg) => msg,
        Err(Error::Truncated) if kind == TransportKind::Udp => {
            log::info!("response truncated over UDP, retrying with TCP");
            kind = TransportKind::Tcp;
            transport::send(kind, &cfg, &query).await?
        }
        Err(e) => return Err(e),
    };
    let elapsed_ms = start.elapsed().as_millis() as u64;

    let elapsed = if args.stats { Some(elapsed_ms) } else { None };
    let out = output::render(args.format, args.short, &response, elapsed);
    print!("{out}");

    Ok(())
}

fn resolve_name(args: &cli::Args) -> Result<Name> {
    let raw = if args.reverse {
        args.name
            .parse::<std::net::IpAddr>()
            .map_err(|_| Error::InvalidName(format!("'{}' is not a valid IP for -x", args.name)))
            .map(|ip| match ip {
                std::net::IpAddr::V4(v4) => {
                    let o = v4.octets();
                    format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
                }
                std::net::IpAddr::V6(v6) => {
                    let nibbles: String = v6
                        .to_bits()
                        .to_be_bytes()
                        .iter()
                        .flat_map(|b| [b >> 4, b & 0xf])
                        .rev()
                        .map(|n| format!("{n:x}"))
                        .collect::<Vec<_>>()
                        .join(".");
                    format!("{nibbles}.ip6.arpa.")
                }
            })?
    } else {
        if args.name.ends_with('.') {
            args.name.clone()
        } else {
            format!("{}.", args.name)
        }
    };

    Name::from_ascii(&raw).map_err(|e| Error::InvalidName(format!("{raw}: {e}")))
}

fn build_query(name: &Name, qtype: RecordType, args: &cli::Args) -> Message {
    let mut msg = Message::query();

    msg.metadata.recursion_desired = !args.no_rd;
    msg.metadata.authoritative = args.aa;
    msg.metadata.authentic_data = args.ad;
    msg.metadata.checking_disabled = args.cd;

    let mut q = Query::new();
    q.set_name(name.clone());
    q.set_query_type(qtype);
    q.set_query_class(args.qclass);
    msg.add_query(q);

    if args.dnssec {
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.set_max_payload(4096);
        msg.set_edns(edns);
    }

    msg
}
