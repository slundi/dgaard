use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use tokio::sync::Semaphore;

use digaard::cli::{DohMethod as CliDohMethod, TlsOpts};
use digaard::dnssec::{TrustAnchors, Verdict, classify, parse_trust_anchor_file};
use digaard::error::{Error, Result};
use digaard::geoip::GeoIpDb;
use digaard::output::{RenderOpts, Rendered};
use digaard::query::{QueryFlags, build_query, pad_message, resolve_name};
use digaard::stats::Stats;
use digaard::transport::{
    DohMethod, DohSettings, ServerPicker, ServerStrategy, TlsSettings, TransportConfig,
    TransportKind, parse_server_spec,
};
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

    // rustls needs a global CryptoProvider before first ClientConfig build.
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let mut targets: Vec<String> = args.names.clone();
    if let Some(path) = &args.file {
        targets.extend(read_targets_from(path)?);
    }
    if targets.is_empty() {
        return Err(Error::InvalidName(
            "no domain names given (positional or -f/--file)".to_string(),
        ));
    }

    let picker = Arc::new(build_server_picker(&args)?);
    let trust_anchors = Arc::new(load_trust_anchors(&args.trust_anchor_files)?);
    let batch = targets.len() > 1;
    let concurrency = args
        .concurrency
        .unwrap_or_else(|| num_cpus().min(MAX_CONCURRENCY))
        .max(1);
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let geoip = if let Some(path) = &args.mmdb {
        match GeoIpDb::open(path) {
            Ok(db) => Some(Arc::new(db)),
            Err(e) => {
                eprintln!("warning: --mmdb {path}: {e}");
                None
            }
        }
    } else {
        None
    };

    let opts = RenderOpts {
        format: args.format,
        short: args.short,
        color: args.color,
        batch,
        edge: args.edge,
        hex: args.hex,
        geoip,
        country_format: args.country_format,
    };

    let mut handles = Vec::with_capacity(targets.len());
    for target in &targets {
        let target = target.clone();
        let picker = Arc::clone(&picker);
        let semaphore = Arc::clone(&semaphore);
        let args = args.clone();
        let anchors = Arc::clone(&trust_anchors);
        handles.push(tokio::spawn(async move {
            let _permit = semaphore.acquire_owned().await.expect("semaphore closed");
            do_one(&target, &args, &picker, &anchors).await
        }));
    }

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let mut first_error: Option<Error> = None;
    let mut stats = Stats::new();

    for (target, handle) in targets.iter().zip(handles) {
        match handle.await.expect("join") {
            Ok(one) => {
                stats.record_ok(one.elapsed_ms);
                let item = Rendered {
                    query: target,
                    response: &one.response,
                    wire: &one.wire,
                    elapsed_ms: if args.stats {
                        Some(one.elapsed_ms)
                    } else {
                        None
                    },
                    verdict: one.verdict.as_ref(),
                };
                let rendered = output::render_batch(&opts, std::slice::from_ref(&item));
                lock.write_all(rendered.as_bytes()).map_err(Error::Io)?;
            }
            Err(e) => {
                stats.record_err();
                eprintln!("{target}: {e}");
                first_error.get_or_insert(e);
            }
        }
    }
    lock.flush().map_err(Error::Io)?;

    if args.stats && stats.len() > 1 {
        eprint!("{}", stats.summary().to_stderr_lines());
    }

    if let Some(e) = first_error {
        return Err(e);
    }

    Ok(())
}

fn load_trust_anchors(files: &[String]) -> Result<TrustAnchors> {
    let mut anchors = TrustAnchors::new();
    for path in files {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Transport(format!("--trust-anchor: read {path}: {e}")))?;
        let parsed = parse_trust_anchor_file(&text)
            .map_err(|e| Error::Transport(format!("--trust-anchor {path}: {e}")))?;
        for k in parsed.drain() {
            anchors.add_dnskey(k.0, k.1);
        }
    }
    Ok(anchors)
}

fn build_server_picker(args: &cli::Args) -> Result<ServerPicker> {
    let servers = if args.servers.is_empty() {
        vec!["8.8.8.8".to_string()]
    } else {
        args.servers.clone()
    };

    let mut configs = Vec::with_capacity(servers.len());
    for spec in servers {
        let (host, spec_port) = parse_server_spec(&spec).map_err(Error::Transport)?;
        let port = spec_port
            .or(args.port)
            .unwrap_or_else(|| args.transport.default_port());
        let tls = build_tls_settings(&args.tls)?;
        let doh = DohSettings {
            method: match args.doh.method {
                CliDohMethod::Get => DohMethod::Get,
                CliDohMethod::Post => DohMethod::Post,
            },
            path: args.doh.path.clone(),
        };
        configs.push(Arc::new(TransportConfig {
            server: host,
            port,
            timeout_ms: args.timeout_ms,
            retry: args.retry,
            ipv4_only: args.ipv4,
            ipv6_only: args.ipv6,
            tls,
            doh,
        }));
    }

    Ok(ServerPicker::new(configs, args.server_strategy))
}

fn build_tls_settings(opts: &TlsOpts) -> Result<TlsSettings> {
    let mut extra_ca_pem = Vec::with_capacity(opts.ca_files.len());
    for path in &opts.ca_files {
        let bytes = std::fs::read(path)
            .map_err(|e| Error::Transport(format!("--tls-ca: read {path}: {e}")))?;
        extra_ca_pem.push(bytes);
    }
    Ok(TlsSettings {
        servername: opts.servername.clone(),
        insecure: opts.insecure,
        extra_ca_pem,
    })
}

struct QueryOutcome {
    response: Message,
    wire: Vec<u8>,
    elapsed_ms: u64,
    verdict: Option<Verdict>,
}

async fn do_one(
    target: &str,
    args: &cli::Args,
    picker: &ServerPicker,
    anchors: &TrustAnchors,
) -> Result<QueryOutcome> {
    let name = resolve_name(target, args.reverse)?;
    let qtype = if args.reverse {
        RecordType::PTR
    } else {
        args.qtype
    };

    // --validate implies --dnssec (we need RRSIGs to classify).
    let dnssec_ok = args.dnssec || args.validate;

    let flags = QueryFlags {
        recursion_desired: !args.no_rd,
        authoritative: args.aa,
        authentic_data: args.ad,
        checking_disabled: args.cd,
        dnssec_ok,
    };

    let mut query = build_query(&name, qtype, args.qclass, flags, &args.edns)?;
    if let Some(block) = args.edns.pad {
        pad_message(&mut query, block)?;
    }

    let start = Instant::now();
    let (response, wire) = match picker.strategy() {
        ServerStrategy::Race => race_send(picker, args.transport, &query).await?,
        _ => send_with_fallback(picker.next(), args.transport, &query).await?,
    };
    let elapsed_ms = start.elapsed().as_millis() as u64;

    let verdict = if args.validate {
        Some(classify(&response, anchors))
    } else {
        None
    };

    Ok(QueryOutcome {
        response,
        wire,
        elapsed_ms,
        verdict,
    })
}

async fn send_with_fallback(
    cfg: Arc<TransportConfig>,
    initial_kind: TransportKind,
    query: &Message,
) -> Result<(Message, Vec<u8>)> {
    let mut kind = initial_kind;
    match transport::send_with_wire(kind, &cfg, query).await {
        Ok(v) => Ok(v),
        Err(Error::Truncated) if kind == TransportKind::Udp => {
            log::info!("response truncated over UDP, retrying with TCP");
            kind = TransportKind::Tcp;
            transport::send_with_wire(kind, &cfg, query).await
        }
        Err(e) => Err(e),
    }
}

async fn race_send(
    picker: &ServerPicker,
    kind: TransportKind,
    query: &Message,
) -> Result<(Message, Vec<u8>)> {
    let mut set = tokio::task::JoinSet::new();
    for cfg in picker.all() {
        let cfg = Arc::clone(cfg);
        let query = query.clone();
        set.spawn(async move { send_with_fallback(cfg, kind, &query).await });
    }
    let mut last_err: Option<Error> = None;
    while let Some(res) = set.join_next().await {
        match res.expect("join") {
            Ok(v) => {
                set.abort_all();
                return Ok(v);
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or(Error::Timeout))
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
