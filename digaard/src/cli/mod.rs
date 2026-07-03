use bpaf::*;
use hickory_proto::rr::{DNSClass, RecordType};

use crate::output::OutputFormat;
use crate::transport::TransportKind;

#[derive(Debug, Clone)]
pub struct Args {
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub transport: TransportKind,
    pub format: OutputFormat,
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
    pub name: String,
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

// ── server ────────────────────────────────────────────────────────────────────

fn server() -> impl Parser<Option<String>> {
    let flag = short('s')
        .long("server")
        .help("Nameserver address (IP or hostname)")
        .argument::<String>("SERVER")
        .optional();

    // Accept a bare token that starts with '@', e.g. @8.8.8.8, anywhere on the command line.
    // `any()` returns None (leaves arg in place) for tokens that don't start with '@'.
    let at_token = any::<String, _, _>("@SERVER", |s: String| {
        s.strip_prefix('@').map(str::to_owned)
    })
    .anywhere()
    .optional();

    construct!([flag, at_token])
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
    construct!([udp, tcp, tls, https]).fallback(TransportKind::Udp)
}

// ── output format ─────────────────────────────────────────────────────────────

fn format() -> impl Parser<OutputFormat> {
    let text = long("text")
        .help("Dig-style text output (default)")
        .req_flag(OutputFormat::Text);
    let json = short('j')
        .long("json")
        .help("JSON output")
        .req_flag(OutputFormat::Json);
    construct!([text, json]).fallback(OutputFormat::Text)
}

// ── top-level ─────────────────────────────────────────────────────────────────

pub fn parse() -> Args {
    let name = positional::<String>("NAME").help("Domain name to query");
    let qtype = qtype();
    let qclass = qclass();
    let server = server();

    let port = short('p')
        .long("port")
        .help("Nameserver port (default depends on transport)")
        .argument::<u16>("PORT")
        .optional();

    let transport = transport();
    let format = format();

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
        .help("Print elapsed time and message size after the response")
        .switch();

    construct!(Args {
        qtype,
        qclass,
        server,
        port,
        transport,
        format,
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
        name,
    })
    .to_options()
    .descr("A modern DNS lookup CLI")
    .footer(
        "Examples:\n  digaard example.com\n  digaard -t MX gmail.com @8.8.8.8\n  digaard -x 1.1.1.1\n  digaard --tls example.com @1.1.1.1",
    )
    .version(env!("CARGO_PKG_VERSION"))
    .run()
}
