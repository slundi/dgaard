use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::{Edns, Message, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::sync::Semaphore;

use digaard::error::{Error, Result};
use digaard::output::{RenderOpts, Rendered};
use digaard::transport::{TransportConfig, TransportKind};
use digaard::{cli, output, transport};

const MAX_CONCURRENCY: usize = 32;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = cli::parse();

    init_logger(args.verbose);

    let mut targets: Vec<String> = args.names.clone();
    if let Some(path) = &args.file {
        targets.extend(read_targets_from(path)?);
    }
    if targets.is_empty() {
        return Err(Error::InvalidName(
            "no domain names given (positional or -f/--file)".to_string(),
        ));
    }

    let server = args.server.as_deref().unwrap_or("8.8.8.8").to_owned();
    let port = args.port.unwrap_or_else(|| args.transport.default_port());

    let cfg = Arc::new(TransportConfig {
        server,
        port,
        timeout_ms: args.timeout_ms,
        retry: args.retry,
        ipv4_only: args.ipv4,
        ipv6_only: args.ipv6,
    });

    let batch = targets.len() > 1;
    let concurrency = args
        .concurrency
        .unwrap_or_else(|| num_cpus().min(MAX_CONCURRENCY))
        .max(1);
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let opts = RenderOpts {
        format: args.format,
        short: args.short,
        color: args.color,
        batch,
    };

    // Fan out with bounded concurrency, preserving input order in the result Vec.
    let mut handles = Vec::with_capacity(targets.len());
    for target in &targets {
        let target = target.clone();
        let cfg = Arc::clone(&cfg);
        let semaphore = Arc::clone(&semaphore);
        let args = args.clone();
        handles.push(tokio::spawn(async move {
            let _permit = semaphore.acquire_owned().await.expect("semaphore closed");
            do_one(&target, &args, &cfg).await
        }));
    }

    // Emit results in submission order.
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let mut first_error: Option<Error> = None;

    for (target, handle) in targets.iter().zip(handles) {
        match handle.await.expect("join") {
            Ok(one) => {
                let item = Rendered {
                    query: target,
                    response: &one.response,
                    elapsed_ms: if args.stats {
                        Some(one.elapsed_ms)
                    } else {
                        None
                    },
                };
                let rendered = output::render_batch(opts, std::slice::from_ref(&item));
                lock.write_all(rendered.as_bytes()).map_err(Error::Io)?;
            }
            Err(e) => {
                eprintln!("{target}: {e}");
                first_error.get_or_insert(e);
            }
        }
    }
    lock.flush().map_err(Error::Io)?;

    if let Some(e) = first_error {
        return Err(e);
    }

    Ok(())
}

struct QueryOutcome {
    response: Message,
    elapsed_ms: u64,
}

async fn do_one(target: &str, args: &cli::Args, cfg: &TransportConfig) -> Result<QueryOutcome> {
    let name = resolve_name(target, args.reverse)?;
    let qtype = if args.reverse {
        RecordType::PTR
    } else {
        args.qtype
    };

    let query = build_query(&name, qtype, args);
    let mut kind = args.transport;

    let start = Instant::now();
    let response = match transport::send(kind, cfg, &query).await {
        Ok(msg) => msg,
        Err(Error::Truncated) if kind == TransportKind::Udp => {
            log::info!("response truncated over UDP, retrying with TCP");
            kind = TransportKind::Tcp;
            transport::send(kind, cfg, &query).await?
        }
        Err(e) => return Err(e),
    };
    let elapsed_ms = start.elapsed().as_millis() as u64;

    Ok(QueryOutcome {
        response,
        elapsed_ms,
    })
}

fn read_targets_from(path: &str) -> Result<Vec<String>> {
    let reader: Box<dyn BufRead> = if path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(
            std::fs::File::open(path).map_err(|e| Error::Transport(format!("open {path}: {e}")))?,
        ))
    };

    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(Error::Io)?;
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(trimmed.to_string());
    }
    Ok(out)
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

fn init_logger(verbosity: usize) {
    // Only override RUST_LOG if the user asked for more verbosity via -v/-vv/-vvv.
    let level = match verbosity {
        0 => None,
        1 => Some("info"),
        2 => Some("debug"),
        _ => Some("trace"),
    };
    let mut builder = env_logger::Builder::from_default_env();
    if let Some(lvl) = level {
        builder.parse_filters(lvl);
    }
    builder.init();
}

fn resolve_name(raw_name: &str, reverse: bool) -> Result<Name> {
    let raw = if reverse {
        raw_name
            .parse::<std::net::IpAddr>()
            .map_err(|_| Error::InvalidName(format!("'{raw_name}' is not a valid IP for -x")))
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
    } else if raw_name.ends_with('.') {
        raw_name.to_string()
    } else {
        format!("{raw_name}.")
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
