use bpaf::*;
use hickory_proto::rr::{DNSClass, RecordType};

use crate::output::{ColorMode, OutputFormat};
use crate::transport::{ServerStrategy, TransportKind};

/// EDNS(0) OPT options that shape the outgoing query.
#[derive(Debug, Clone)]
pub struct EdnsOpts {
    pub enabled: bool,
    pub bufsize: Option<u16>,
    pub subnet: Option<String>,
    pub nsid: bool,
    pub cookie: Option<Vec<u8>>,
    /// Block size in bytes; `None` = padding disabled.
    pub pad: Option<u16>,
}

/// TLS/PKI options shared by DoT and DoH.
#[derive(Debug, Clone)]
pub struct TlsOpts {
    /// Override SNI / expected certificate name. Defaults to the server host.
    pub servername: Option<String>,
    /// Skip certificate verification. Debugging-only.
    pub insecure: bool,
    /// Path(s) to PEM files of additional trust roots.
    pub ca_files: Vec<String>,
}

/// DoH-only options.
#[derive(Debug, Clone)]
pub struct DohOpts {
    /// HTTP method (GET or POST). Default POST.
    pub method: DohMethod,
    /// URL path. Default "/dns-query".
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohMethod {
    Get,
    Post,
}

#[derive(Debug, Clone)]
pub struct Args {
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub servers: Vec<String>,
    pub server_strategy: ServerStrategy,
    pub port: Option<u16>,
    pub transport: TransportKind,
    pub format: OutputFormat,
    pub color: ColorMode,
    pub short: bool,
    pub no_rd: bool,
    pub dnssec: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub aa: bool,
    pub ad: bool,
    pub cd: bool,
    pub reverse: bool,
    pub timeout_ms: u64,
    pub retry: u32,
    pub verbose: usize,
    pub stats: bool,
    pub file: Option<String>,
    pub concurrency: Option<usize>,
    pub edns: EdnsOpts,
    pub tls: TlsOpts,
    pub doh: DohOpts,
    pub edge: bool,
    pub hex: bool,
    pub validate: bool,
    pub trust_anchor_files: Vec<String>,
    pub names: Vec<String>,
}

// ── record type ───────────────────────────────────────────────────────────────

fn qtype() -> impl Parser<RecordType> {
    short('t')
        .long("type")
        .help("Record type: A, AAAA, MX, NS, TXT, SOA, PTR, SRV, CAA, DNSKEY, DS, …")
        .argument::<String>("TYPE")
        .parse(|s| {
            s.parse::<RecordType>()
                .map_err(|_| format!("unknown record type '{s}'"))
        })
        .fallback(RecordType::A)
}

// ── DNS class ─────────────────────────────────────────────────────────────────

fn qclass() -> impl Parser<DNSClass> {
    short('c')
        .long("class")
        .help("Query class: IN (default), CH, HS, ANY")
        .argument::<String>("CLASS")
        .parse(|s| match s.to_ascii_uppercase().as_str() {
            "IN" | "INTERNET" => Ok(DNSClass::IN),
            "CH" | "CHAOS" => Ok(DNSClass::CH),
            "HS" | "HESIOD" => Ok(DNSClass::HS),
            "ANY" => Ok(DNSClass::ANY),
            other => Err(format!("unknown class '{other}'")),
        })
        .fallback(DNSClass::IN)
}

// ── servers ───────────────────────────────────────────────────────────────────

fn servers() -> impl Parser<Vec<String>> {
    let flag = short('s')
        .long("server")
        .help("Nameserver address (IP or hostname). Repeatable.")
        .argument::<String>("SERVER")
        .many();

    // Accept `@server` bare tokens too (multi allowed via .many()).
    let at_token = any::<String, _, _>("@SERVER", |s: String| {
        s.strip_prefix('@').map(str::to_owned)
    })
    .anywhere()
    .many();

    construct!(flag, at_token).map(|(mut a, b)| {
        a.extend(b);
        a
    })
}

fn server_strategy() -> impl Parser<ServerStrategy> {
    long("server-strategy")
        .help("How to select among multiple servers: first (default), race, round-robin")
        .argument::<String>("MODE")
        .parse(|s| match s.to_ascii_lowercase().as_str() {
            "first" | "" => Ok(ServerStrategy::First),
            "race" => Ok(ServerStrategy::Race),
            "round-robin" | "rr" | "roundrobin" => Ok(ServerStrategy::RoundRobin),
            other => Err(format!("unknown --server-strategy '{other}'")),
        })
        .fallback(ServerStrategy::First)
}

// ── transport ─────────────────────────────────────────────────────────────────

fn transport() -> impl Parser<TransportKind> {
    let udp = long("udp")
        .help("Plain UDP (default)")
        .req_flag(TransportKind::Udp);
    let tcp = long("tcp").help("Force TCP").req_flag(TransportKind::Tcp);
    let tls = long("tls")
        .help("DNS over TLS (DoT, port 853)")
        .req_flag(TransportKind::Tls);
    let https = long("https")
        .help("DNS over HTTPS (DoH, port 443)")
        .req_flag(TransportKind::Https);
    let quic = long("quic")
        .help("DNS over QUIC (DoQ, RFC 9250, port 853)")
        .req_flag(TransportKind::Quic);
    construct!([udp, tcp, tls, https, quic]).fallback(TransportKind::Udp)
}

// ── output format ─────────────────────────────────────────────────────────────

fn format() -> impl Parser<OutputFormat> {
    let text = long("text")
        .help("Dig-style text output (default)")
        .req_flag(OutputFormat::Text);
    let json = long("json")
        .help("JSON output (line-delimited when multiple queries)")
        .req_flag(OutputFormat::Json);
    construct!([text, json]).fallback(OutputFormat::Text)
}

// ── color mode ────────────────────────────────────────────────────────────────

fn color() -> impl Parser<ColorMode> {
    long("color")
        .help("Colorize pretty-print output: auto (default), always, never")
        .argument::<String>("WHEN")
        .parse(|s| match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(ColorMode::Auto),
            "always" | "yes" | "on" => Ok(ColorMode::Always),
            "never" | "no" | "off" => Ok(ColorMode::Never),
            other => Err(format!("unknown color mode '{other}'")),
        })
        .fallback(ColorMode::Auto)
}

// ── EDNS(0) ──────────────────────────────────────────────────────────────────

fn edns_opts() -> impl Parser<EdnsOpts> {
    let enable = long("edns")
        .help("Enable EDNS(0) OPT record (default)")
        .req_flag(true);
    let disable = long("no-edns")
        .help("Disable EDNS(0) OPT record")
        .req_flag(false);
    let enabled = construct!([enable, disable]).fallback(true);

    let bufsize = long("edns-bufsize")
        .help("Advertised UDP payload size in OPT [default: 1232]")
        .argument::<u16>("BYTES")
        .optional();

    let subnet = long("subnet")
        .help("EDNS Client Subnet: PREFIX like 1.2.3.0/24 or 2001:db8::/32")
        .argument::<String>("PREFIX")
        .optional();

    let nsid = long("nsid").help("Request NSID (RFC 5001)").switch();

    let cookie_hex = long("cookie-hex")
        .help("Send DNS Cookie (RFC 7873) with an explicit hex value")
        .argument::<String>("HEX")
        .optional()
        .parse(|opt| -> std::result::Result<Option<Vec<u8>>, String> {
            match opt {
                None => Ok(None),
                Some(s) => Ok(Some(
                    parse_hex(&s).map_err(|e| format!("--cookie-hex: {e}"))?,
                )),
            }
        });
    let cookie_switch = long("cookie")
        .help("Send DNS Cookie (RFC 7873) with 8 random bytes")
        .switch()
        .map(|on| if on { Some(random_cookie()) } else { None });
    let cookie = construct!(cookie_hex, cookie_switch).map(|(a, b)| a.or(b));

    let pad_size = long("pad-size")
        .help("EDNS Padding block size in bytes")
        .argument::<u16>("SIZE")
        .optional();
    let pad_switch = long("pad")
        .help("Enable EDNS Padding (RFC 7830), rounding wire size to a 128-byte block")
        .switch()
        .map(|on| if on { Some(128u16) } else { None });
    let pad = construct!(pad_size, pad_switch).map(|(a, b)| a.or(b));

    construct!(EdnsOpts {
        enabled,
        bufsize,
        subnet,
        nsid,
        cookie,
        pad,
    })
}

// ── TLS opts ──────────────────────────────────────────────────────────────────

fn tls_opts() -> impl Parser<TlsOpts> {
    let servername = long("tls-servername")
        .help("SNI / expected certificate name (defaults to server host)")
        .argument::<String>("NAME")
        .optional();

    let insecure = long("tls-insecure")
        .help("Skip TLS certificate verification (debugging only)")
        .switch();

    let ca_files = long("tls-ca")
        .help("PEM file with additional trust roots. Repeatable.")
        .argument::<String>("FILE")
        .many();

    construct!(TlsOpts {
        servername,
        insecure,
        ca_files,
    })
}

// ── DoH opts ──────────────────────────────────────────────────────────────────

fn doh_opts() -> impl Parser<DohOpts> {
    let method = long("doh-method")
        .help("DoH HTTP method: POST (default) or GET")
        .argument::<String>("METHOD")
        .parse(|s| match s.to_ascii_uppercase().as_str() {
            "POST" => Ok(DohMethod::Post),
            "GET" => Ok(DohMethod::Get),
            other => Err(format!("--doh-method must be GET or POST, got '{other}'")),
        })
        .fallback(DohMethod::Post);

    let path = long("doh-path")
        .help("DoH URL path [default: /dns-query]")
        .argument::<String>("PATH")
        .fallback_with(|| -> std::result::Result<_, String> { Ok("/dns-query".to_string()) });

    construct!(DohOpts { method, path })
}

fn parse_hex(s: &str) -> std::result::Result<Vec<u8>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length: {cleaned}"));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|e| format!("bad hex byte at offset {i}: {e}"))
        })
        .collect()
}

fn random_cookie() -> Vec<u8> {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("system rng");
    buf.to_vec()
}

// ── top-level ─────────────────────────────────────────────────────────────────

pub fn parse() -> Args {
    let names = positional::<String>("NAME")
        .help("Domain name(s) to query; repeat for batch")
        .many();
    let qtype = qtype();
    let qclass = qclass();
    let servers = servers();
    let server_strategy = server_strategy();

    let port = short('p')
        .long("port")
        .help("Nameserver port (default depends on transport)")
        .argument::<u16>("PORT")
        .optional();

    let transport = transport();
    let format = format();
    let color = color();

    let short = {
        use bpaf::short as s;
        s('q')
            .long("short")
            .help("Print only answer records, one per line")
            .switch()
    };

    let no_rd = long("no-rd")
        .help("Clear the Recursion Desired bit")
        .switch();
    let dnssec = long("dnssec").help("Set the DNSSEC OK (DO) bit").switch();
    let ipv4 = bpaf::short('4')
        .help("Use IPv4 for the transport connection")
        .switch();
    let ipv6 = bpaf::short('6')
        .help("Use IPv6 for the transport connection")
        .switch();
    let aa = long("aa").help("Set Authoritative Answer bit").switch();
    let ad = long("ad").help("Set Authenticated Data bit").switch();
    let cd = long("cd").help("Set Checking Disabled bit").switch();

    let reverse = bpaf::short('x')
        .long("reverse")
        .help("Reverse lookup — synthesise PTR query from an IP address")
        .switch();

    let timeout_ms = long("timeout")
        .help("Per-query timeout in milliseconds [default: 5000]")
        .argument::<u64>("MS")
        .fallback(5000);

    let retry = long("retry")
        .help("Number of retries on UDP timeout [default: 2]")
        .argument::<u32>("N")
        .fallback(2);

    let verbose = bpaf::short('v')
        .long("verbose")
        .help("Increase logging verbosity (repeatable: -v, -vv, -vvv)")
        .req_flag(())
        .many()
        .map(|v| v.len());

    let stats = long("stats")
        .help("Print elapsed time and message size after each response")
        .switch();

    let file = bpaf::short('f')
        .long("file")
        .help("Read domains from file, one per line; use '-' for stdin. Blank lines and '#' comments ignored")
        .argument::<String>("PATH")
        .optional();

    let concurrency = bpaf::short('j')
        .long("concurrency")
        .help("Max concurrent in-flight queries [default: min(cpus, 32)]")
        .argument::<usize>("N")
        .optional();

    let edns = edns_opts();
    let tls = tls_opts();
    let doh = doh_opts();

    let edge = long("edge")
        .help("Decode Extended DNS Errors (RFC 8914) into ADDITIONAL section")
        .switch();

    let hex = long("hex")
        .help("Print raw response wire bytes as a hex dump instead of parsed records")
        .switch();

    let validate = long("validate")
        .help("Classify response as SECURE / INSECURE / BOGUS (implies --dnssec)")
        .switch();

    let trust_anchor_files = long("trust-anchor")
        .help("BIND-style trust-anchor file with DNSKEY records. Repeatable.")
        .argument::<String>("FILE")
        .many();

    construct!(Args {
        qtype,
        qclass,
        servers,
        server_strategy,
        port,
        transport,
        format,
        color,
        short,
        no_rd,
        dnssec,
        ipv4,
        ipv6,
        aa,
        ad,
        cd,
        reverse,
        timeout_ms,
        retry,
        verbose,
        stats,
        file,
        concurrency,
        edns,
        tls,
        doh,
        edge,
        hex,
        validate,
        trust_anchor_files,
        names,
    })
    .to_options()
    .descr("A modern DNS lookup CLI")
    .footer(
        "Examples:\n  \
         digaard example.com\n  \
         digaard -t MX gmail.com @8.8.8.8\n  \
         digaard --tls example.com @1.1.1.1\n  \
         digaard --https example.com @1.1.1.1 --doh-method GET\n  \
         digaard -s 1.1.1.1 -s 9.9.9.9 --server-strategy race example.com\n  \
         digaard --tls-insecure --tls-servername dns.example --tls dot.example.com\n  \
         digaard -x 1.1.1.1",
    )
    .version(env!("CARGO_PKG_VERSION"))
    .run()
}
