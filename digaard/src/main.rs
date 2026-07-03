use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use tokio::sync::Semaphore;

use digaard::error::{Error, Result};
use digaard::output::{RenderOpts, Rendered};
use digaard::query::{QueryFlags, build_query, pad_message, resolve_name};
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
        edge: args.edge,
        hex: args.hex,
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
                    wire: &one.wire,
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
    wire: Vec<u8>,
    elapsed_ms: u64,
}

async fn do_one(target: &str, args: &cli::Args, cfg: &TransportConfig) -> Result<QueryOutcome> {
    let name = resolve_name(target, args.reverse)?;
    let qtype = if args.reverse {
        RecordType::PTR
    } else {
        args.qtype
    };

    let flags = QueryFlags {
        recursion_desired: !args.no_rd,
        authoritative: args.aa,
        authentic_data: args.ad,
        checking_disabled: args.cd,
        dnssec_ok: args.dnssec,
    };

    let mut query = build_query(&name, qtype, args.qclass, flags, &args.edns)?;
    if let Some(block) = args.edns.pad {
        pad_message(&mut query, block)?;
    }

    let mut kind = args.transport;
    let start = Instant::now();
    let (response, wire) = match transport::send_with_wire(kind, cfg, &query).await {
        Ok(v) => v,
        Err(Error::Truncated) if kind == TransportKind::Udp => {
            log::info!("response truncated over UDP, retrying with TCP");
            kind = TransportKind::Tcp;
            transport::send_with_wire(kind, cfg, &query).await?
        }
        Err(e) => return Err(e),
    };
    let elapsed_ms = start.elapsed().as_millis() as u64;

    Ok(QueryOutcome {
        response,
        wire,
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
