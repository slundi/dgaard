use crate::CONFIG;
use crate::config::QueryLogLevel;
use crate::model::{StatAction, StatBlockReason, StatError, StatEvent};
use crate::stats::{DOMAIN_MAP_CAP, StatsReceiver};
use lru::LruCache;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Maximum number of simultaneously connected stats clients. A flapping
/// dashboard would otherwise grow the client list without bound.
const MAX_CLIENTS: usize = 8;

/// Messages queued per client. A client that falls this far behind is
/// disconnected rather than allowed to stall the collector.
const CLIENT_QUEUE: usize = 1024;

/// Longest a single write to a client may take before it is disconnected.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Permissions of the stats socket: it exposes queried domains and client
/// IPs, so only the daemon's user and group may connect, whatever the umask.
const SOCKET_MODE: u32 = 0o660;

/// One connected stats client, as seen by the collector: the sending end of
/// its bounded queue. A dedicated task owns the socket and does the writes.
pub(crate) struct StatsClient {
    tx: mpsc::Sender<Arc<[u8]>>,
}

impl StatsClient {
    /// Start the writer task of a new client: it first sends `snapshot`
    /// (the current domain mappings), then every queued message, each write
    /// bounded by `write_timeout`. The task ends — and the collector drops
    /// the client — on a write error or timeout.
    pub(crate) fn spawn(
        mut stream: tokio::net::UnixStream,
        snapshot: Vec<u8>,
        queue: usize,
        write_timeout: Duration,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<Arc<[u8]>>(queue);
        tokio::spawn(async move {
            if !write_within(&mut stream, &snapshot, write_timeout).await {
                return;
            }
            drop(snapshot);
            while let Some(bytes) = rx.recv().await {
                if !write_within(&mut stream, &bytes, write_timeout).await {
                    return;
                }
            }
        });
        Self { tx }
    }

    /// Queue `bytes` without waiting; false when the client must be dropped
    /// (queue full: too slow; closed: its writer task ended).
    fn offer(&self, bytes: &Arc<[u8]>) -> bool {
        self.tx.try_send(Arc::clone(bytes)).is_ok()
    }
}

/// Cap on distinct clients and blocked domains tracked per summary window,
/// so a scan or a burst of random subdomains cannot grow the maps without
/// bound between two summary lines.
const SUMMARY_TRACK_CAP: usize = 4096;

/// Stats collector task that receives events and handles logging/streaming.
///
/// This task:
/// 1. Receives StatMessage events from DNS handlers via MPSC channel
/// 2. Logs per-query verdicts to stdout, filtered by `[log] queries`
/// 3. Prints a `[SUMMARY]` line every `[log] summary_interval_secs`
/// 4. Streams events to connected Unix socket clients
pub(crate) async fn stats_collector_task(
    mut receiver: StatsReceiver,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    // Track domain mappings for logging; capped to avoid unbounded growth.
    let mut domain_map: LruCache<u64, String> =
        LruCache::new(NonZeroUsize::new(DOMAIN_MAP_CAP).unwrap());

    let log_config = CONFIG.load().log.clone();
    let mut query_log = QueryLog::new(log_config.queries);

    // The interval is fixed at startup; the first tick fires one full period
    // after boot rather than immediately (an empty summary is noise).
    let summary_secs = log_config.summary_interval_secs;
    let mut summary_tick = (summary_secs > 0).then(|| {
        let period = std::time::Duration::from_secs(u64::from(summary_secs));
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick
    });

    // Connected socket clients. Capped to MAX_CLIENTS so a misbehaving
    // dashboard that reconnects in a tight loop cannot grow this vec
    // (and the per-event broadcast cost) without bound.
    let mut clients: Vec<StatsClient> = Vec::new();

    // Try to bind the Unix socket
    let socket_path = CONFIG.load().server.stats_socket_path.clone();
    let listener = match setup_unix_socket(&socket_path).await {
        Ok(l) => {
            println!("Stats socket listening on {}", socket_path);
            Some(l)
        }
        Err(e) => {
            eprintln!(
                "Warning: Failed to create stats socket at {}: {}",
                socket_path, e
            );
            None
        }
    };

    loop {
        tokio::select! {
            biased;

            // Check for shutdown
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    // Drain remaining messages before exit
                    while let Ok(msg) = receiver.try_recv() {
                        process_stat_message(&msg, &mut domain_map, &mut clients, &mut query_log)
                            .await;
                    }
                    // Clean up socket file in the blocking pool to avoid
                    // stalling the runtime on slow filesystems.
                    if !socket_path.is_empty() {
                        let cleanup_path = socket_path.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            let _ = remove_stale_socket(std::path::Path::new(&cleanup_path));
                        })
                        .await;
                    }
                    break;
                }
            }

            // Accept new Unix socket connections
            result = async {
                match &listener {
                    Some(l) => l.accept().await,
                    None => std::future::pending().await,
                }
            } => {
                match result {
                    Ok((stream, _addr)) => {
                        if clients.len() >= MAX_CLIENTS {
                            eprintln!(
                                "stats: refusing new client, MAX_CLIENTS ({MAX_CLIENTS}) reached"
                            );
                            // Dropping `stream` closes the connection immediately.
                            drop(stream);
                            continue;
                        }
                        clients.retain(|client| !client.tx.is_closed());
                        println!("Stats client connected ({} total)", clients.len() + 1);
                        // Its own task sends the current domain mappings,
                        // then follows the live stream.
                        clients.push(StatsClient::spawn(
                            stream,
                            domain_mappings_snapshot(&domain_map),
                            CLIENT_QUEUE,
                            CLIENT_WRITE_TIMEOUT,
                        ));
                    }
                    Err(e) => {
                        eprintln!("Error accepting stats connection: {}", e);
                    }
                }
            }

            // Periodic summary. Polled before `recv` so a busy channel under
            // `biased` cannot starve it.
            _ = async {
                match summary_tick.as_mut() {
                    Some(tick) => {
                        tick.tick().await;
                    }
                    None => std::future::pending().await,
                }
            } => {
                println!("{}", query_log.summary.take_line(summary_secs, &domain_map));
            }

            // Process stat messages
            msg = receiver.recv() => {
                match msg {
                    Some(msg) => {
                        // Per-query level is hot-reloadable via SIGHUP.
                        query_log.level = CONFIG.load().log.queries;
                        process_stat_message(&msg, &mut domain_map, &mut clients, &mut query_log)
                            .await
                    }
                    None => break, // All senders dropped
                }
            }
        }
    }
}

/// Write all of `bytes` within `limit`; false on error or timeout.
async fn write_within(stream: &mut tokio::net::UnixStream, bytes: &[u8], limit: Duration) -> bool {
    use tokio::io::AsyncWriteExt;

    matches!(
        tokio::time::timeout(limit, stream.write_all(bytes)).await,
        Ok(Ok(()))
    )
}

/// Remove a leftover stats socket at `path`. Only a socket is removed: a
/// regular file, directory or symlink there is an error, because the daemon
/// often runs as root and the path comes from configuration.
fn remove_stale_socket(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;

    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} exists and is not a socket; refusing to remove it",
                path.display()
            ),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Set up the Unix domain socket for stats streaming.
///
/// The socket is bound under a temporary name, given [`SOCKET_MODE`], then
/// renamed into place, so it never exists at `path` with umask-derived
/// permissions. Filesystem work runs in the blocking pool so the executor
/// isn't stalled on slow flash or NFS during startup.
pub(crate) async fn setup_unix_socket(path: &str) -> std::io::Result<tokio::net::UnixListener> {
    if path.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Stats socket path is empty",
        ));
    }

    let path_owned = std::path::PathBuf::from(path);
    let std_listener = tokio::task::spawn_blocking(move || {
        use std::os::unix::fs::PermissionsExt;

        if let Some(parent) = path_owned.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        remove_stale_socket(&path_owned)?;
        let staging = path_owned.with_extension(format!("tmp{}", std::process::id()));
        remove_stale_socket(&staging)?;
        let listener = std::os::unix::net::UnixListener::bind(&staging)?;
        let placed =
            std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(SOCKET_MODE))
                .and_then(|()| std::fs::rename(&staging, &path_owned));
        if let Err(e) = placed {
            let _ = std::fs::remove_file(&staging);
            return Err(e);
        }
        listener.set_nonblocking(true)?;
        Ok::<_, std::io::Error>(listener)
    })
    .await
    .map_err(|e| std::io::Error::other(format!("setup_unix_socket join: {e}")))??;

    tokio::net::UnixListener::from_std(std_listener)
}

/// Every known domain mapping, serialized back to back: what a new client
/// receives before the live stream.
pub(crate) fn domain_mappings_snapshot(domain_map: &LruCache<u64, String>) -> Vec<u8> {
    use crate::model::StatMessage;

    let mut snapshot = Vec::new();
    for (&hash, domain) in domain_map.iter() {
        let msg = StatMessage::DomainMapping {
            hash,
            domain: domain.clone(),
        };
        snapshot.extend_from_slice(&msg.serialize());
    }
    snapshot
}

/// Stdout logging state owned by the collector task.
pub(crate) struct QueryLog {
    /// Per-query verdicts to print; refreshed from `CONFIG` on every event.
    pub(crate) level: QueryLogLevel,
    /// Counters for the periodic `[SUMMARY]` line.
    pub(crate) summary: TrafficSummary,
}

impl QueryLog {
    pub(crate) fn new(level: QueryLogLevel) -> Self {
        Self {
            level,
            summary: TrafficSummary::default(),
        }
    }
}

/// Per-window traffic counters behind the periodic `[SUMMARY]` line.
///
/// Fed from the stats channel, so events dropped under backpressure (see
/// `stats_events_dropped_total`) are missing here too.
#[derive(Default)]
pub(crate) struct TrafficSummary {
    queries: u64,
    blocked: u64,
    suspicious: u64,
    /// Queries answered SERVFAIL (upstream failure, DNSSEC bogus).
    errors: u64,
    clients: HashSet<[u8; 16]>,
    blocked_domains: HashMap<u64, u32>,
}

impl TrafficSummary {
    pub(crate) fn record(&mut self, event: &StatEvent) {
        self.queries += 1;
        match event.action {
            StatAction::Blocked(_) => {
                self.blocked += 1;
                let tracked = self.blocked_domains.len();
                match self.blocked_domains.entry(event.domain_hash) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        *entry.get_mut() += 1;
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        if tracked < SUMMARY_TRACK_CAP {
                            entry.insert(1);
                        }
                    }
                }
            }
            StatAction::Suspicious(_) | StatAction::HighlySuspicious(_) => self.suspicious += 1,
            StatAction::Error(_) => self.errors += 1,
            StatAction::Allowed
            | StatAction::Proxied
            | StatAction::AllowedWithOverride
            | StatAction::Cached => {}
        }
        if self.clients.len() < SUMMARY_TRACK_CAP {
            self.clients.insert(event.client_ip);
        }
    }

    /// Render the summary for the elapsed window and reset the counters.
    ///
    /// The maps are dropped rather than cleared so a one-off burst does not
    /// pin its peak allocation for the rest of the process lifetime.
    pub(crate) fn take_line(
        &mut self,
        window_secs: u32,
        domain_map: &LruCache<u64, String>,
    ) -> String {
        use std::fmt::Write;

        let window = std::mem::take(self);
        let blocked_pct = if window.queries == 0 {
            0.0
        } else {
            window.blocked as f64 * 100.0 / window.queries as f64
        };
        let clients_capped = if window.clients.len() >= SUMMARY_TRACK_CAP {
            "+"
        } else {
            ""
        };
        let mut line = format!(
            "[SUMMARY] last {window_secs}s: queries={} blocked={} ({blocked_pct:.1}%) suspicious={} errors={} clients={}{clients_capped}",
            window.queries,
            window.blocked,
            window.suspicious,
            window.errors,
            window.clients.len(),
        );
        if let Some((hash, count)) = window
            .blocked_domains
            .iter()
            .max_by_key(|(_, count)| **count)
        {
            let domain = domain_map.peek(hash).map_or("<unknown>", String::as_str);
            let _ = write!(line, " top_blocked={domain} ({count})");
        }
        line
    }
}

/// Format the stdout line for one event, or `None` when `level` filters it
/// out. The domain lookup and IP formatting only happen for printed lines.
pub(crate) fn query_log_line(
    event: &StatEvent,
    domain_map: &mut LruCache<u64, String>,
    level: QueryLogLevel,
) -> Option<String> {
    let (min_level, tag, reason) = match &event.action {
        StatAction::Blocked(reason) => (
            QueryLogLevel::Blocked,
            "BLOCK",
            Some(stat_block_reason_str(reason)),
        ),
        StatAction::HighlySuspicious(reason) => (
            QueryLogLevel::Suspicious,
            "SUSPICIOUS:HIGH",
            Some(stat_block_reason_str(reason)),
        ),
        StatAction::Suspicious(reason) => (
            QueryLogLevel::Suspicious,
            "SUSPICIOUS",
            Some(stat_block_reason_str(reason)),
        ),
        // Failures are shown with blocks: the client got no answer either.
        StatAction::Error(kind) => (
            QueryLogLevel::Blocked,
            "SERVFAIL",
            Some(stat_error_str(*kind).to_owned()),
        ),
        StatAction::Allowed => (QueryLogLevel::All, "ALLOW", None),
        StatAction::Proxied => (QueryLogLevel::All, "PROXY", None),
        StatAction::AllowedWithOverride => (QueryLogLevel::All, "OVERRIDE", None),
        StatAction::Cached => (QueryLogLevel::All, "CACHE", None),
    };
    if level < min_level {
        return None;
    }

    let domain = domain_map
        .get(&event.domain_hash)
        .map_or("<unknown>", String::as_str);
    let client_ip = format_client_ip(&event.client_ip);
    Some(match reason {
        Some(reason) => format!("[{tag}] {client_ip} -> {domain} ({reason})"),
        None => format!("[{tag}] {client_ip} -> {domain}"),
    })
}

/// Process a single stat message: log to stdout and stream to connected clients.
pub(crate) async fn process_stat_message(
    msg: &crate::model::StatMessage,
    domain_map: &mut LruCache<u64, String>,
    clients: &mut Vec<StatsClient>,
    query_log: &mut QueryLog,
) {
    use crate::model::StatMessage;

    match msg {
        StatMessage::DomainMapping { hash, domain } => {
            domain_map.put(*hash, domain.clone());
        }
        StatMessage::Event(event) => {
            // Every event refreshes its mapping, logged or not, so the map
            // evicts domains nobody queries rather than busy ones — the
            // sender, which refreshes on every send, relies on it.
            domain_map.promote(&event.domain_hash);
            query_log.summary.record(event);
            if let Some(line) = query_log_line(event, domain_map, query_log.level) {
                println!("{line}");
            }
        }
    }

    // Hand the message to every client's queue without waiting: a slow or
    // stuck client is dropped instead of stalling the collector.
    if !clients.is_empty() {
        let bytes: Arc<[u8]> = msg.serialize().into();
        let before = clients.len();
        clients.retain(|client| client.offer(&bytes));
        if clients.len() < before {
            println!(
                "Stats client disconnected (too slow or gone; {} remaining)",
                clients.len()
            );
        }
    }
}

/// Log label of a SERVFAIL cause.
fn stat_error_str(kind: StatError) -> &'static str {
    match kind {
        StatError::Upstream => "upstream failure",
        StatError::DnssecBogus => "dnssec bogus",
    }
}

/// Map a `StatBlockReason` bitflag set to a human-readable label for log output.
/// Multiple active flags are joined with `+`.
fn stat_block_reason_str(reason: &StatBlockReason) -> String {
    let mut parts = Vec::new();
    if reason.contains(StatBlockReason::STATIC_BLACKLIST) {
        parts.push("blocklist");
    }
    if reason.contains(StatBlockReason::ABP_RULE) {
        parts.push("abp-rule");
    }
    if reason.contains(StatBlockReason::HIGH_ENTROPY) {
        parts.push("dga");
    }
    if reason.contains(StatBlockReason::LEXICAL_ANALYSIS) {
        parts.push("lexical");
    }
    if reason.contains(StatBlockReason::BANNED_KEYWORD) {
        parts.push("keyword");
    }
    if reason.contains(StatBlockReason::INVALID_STRUCTURE) {
        parts.push("structure");
    }
    if reason.contains(StatBlockReason::SUSPICIOUS_IDN) {
        parts.push("idn");
    }
    if reason.contains(StatBlockReason::NRD_LIST) {
        parts.push("nrd");
    }
    if reason.contains(StatBlockReason::TLD_EXCLUDED) {
        parts.push("tld");
    }
    if reason.contains(StatBlockReason::SUSPICIOUS) {
        parts.push("suspicious");
    }
    if reason.contains(StatBlockReason::CNAME_CLOAKING) {
        parts.push("cname-cloaking");
    }
    if reason.contains(StatBlockReason::FORBIDDEN_QTYPE) {
        parts.push("forbidden-qtype");
    }
    if reason.contains(StatBlockReason::DNS_REBINDING) {
        parts.push("dns-rebinding");
    }
    if reason.contains(StatBlockReason::LOW_TTL) {
        parts.push("low-ttl");
    }
    if reason.contains(StatBlockReason::ASN_BLOCKED) {
        parts.push("asn-blocked");
    }
    if parts.is_empty() {
        "unknown".to_string()
    } else {
        parts.join("+")
    }
}

/// Format a 16-byte IPv6 address (or IPv4-mapped) for display.
pub(crate) fn format_client_ip(ip_bytes: &[u8; 16]) -> String {
    let v6 = std::net::Ipv6Addr::from(*ip_bytes);
    match v6.to_ipv4_mapped() {
        Some(v4) => v4.to_string(),
        None => v6.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{StatAction, StatBlockReason, StatEvent, StatMessage};

    // ── format_client_ip ─────────────────────────────────────────────────────

    #[test]
    fn format_ipv4_mapped_address() {
        // 127.0.0.1 mapped to IPv6
        let ip: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        let v6 = ip.to_ipv6_mapped();
        let bytes = v6.octets();
        assert_eq!(format_client_ip(&bytes), "127.0.0.1");
    }

    #[test]
    fn format_ipv4_address_192() {
        let ip: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();
        let bytes = ip.to_ipv6_mapped().octets();
        assert_eq!(format_client_ip(&bytes), "192.168.1.1");
    }

    #[test]
    fn format_pure_ipv6_address() {
        // Pure IPv6 address (not IPv4-mapped)
        let ip: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let bytes = ip.octets();
        assert_eq!(format_client_ip(&bytes), "2001:db8::1");
    }

    #[test]
    fn format_loopback_ipv6() {
        let ip: std::net::Ipv6Addr = "::1".parse().unwrap();
        let bytes = ip.octets();
        assert_eq!(format_client_ip(&bytes), "::1");
    }

    // ── stat_block_reason_str ────────────────────────────────────────────────

    #[test]
    fn reason_str_single_flag() {
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::STATIC_BLACKLIST),
            "blocklist"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::ABP_RULE),
            "abp-rule"
        );
        assert_eq!(stat_block_reason_str(&StatBlockReason::HIGH_ENTROPY), "dga");
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::LEXICAL_ANALYSIS),
            "lexical"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::BANNED_KEYWORD),
            "keyword"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::INVALID_STRUCTURE),
            "structure"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::SUSPICIOUS_IDN),
            "idn"
        );
        assert_eq!(stat_block_reason_str(&StatBlockReason::NRD_LIST), "nrd");
        assert_eq!(stat_block_reason_str(&StatBlockReason::TLD_EXCLUDED), "tld");
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::SUSPICIOUS),
            "suspicious"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::CNAME_CLOAKING),
            "cname-cloaking"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::FORBIDDEN_QTYPE),
            "forbidden-qtype"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::DNS_REBINDING),
            "dns-rebinding"
        );
        assert_eq!(stat_block_reason_str(&StatBlockReason::LOW_TTL), "low-ttl");
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::ASN_BLOCKED),
            "asn-blocked"
        );
    }

    #[test]
    fn reason_str_empty_flags_returns_unknown() {
        let empty = StatBlockReason::empty();
        assert_eq!(stat_block_reason_str(&empty), "unknown");
    }

    #[test]
    fn reason_str_multiple_flags_joined_with_plus() {
        let combined = StatBlockReason::HIGH_ENTROPY | StatBlockReason::NRD_LIST;
        let s = stat_block_reason_str(&combined);
        assert!(s.contains("dga"), "expected 'dga' in '{s}'");
        assert!(s.contains("nrd"), "expected 'nrd' in '{s}'");
        assert!(s.contains('+'), "expected '+' separator in '{s}'");
    }

    // ── process_stat_message ─────────────────────────────────────────────────

    fn test_map() -> LruCache<u64, String> {
        LruCache::new(NonZeroUsize::new(1_000).unwrap())
    }

    fn test_log() -> QueryLog {
        QueryLog::new(QueryLogLevel::Blocked)
    }

    fn event_from(client: [u8; 4], domain_hash: u64, action: StatAction) -> StatEvent {
        StatEvent {
            timestamp: 0,
            domain_hash,
            client_ip: std::net::Ipv4Addr::from(client).to_ipv6_mapped().octets(),
            action,
        }
    }

    fn blocked() -> StatAction {
        StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST)
    }

    // ── query_log_line ───────────────────────────────────────────────────────

    #[test]
    fn query_log_line_formats_blocked_with_reason() {
        let mut domain_map = test_map();
        domain_map.put(7, "ads.example".to_string());
        let event = event_from([192, 168, 1, 20], 7, blocked());

        let line = query_log_line(&event, &mut domain_map, QueryLogLevel::Blocked);
        assert_eq!(
            line.as_deref(),
            Some("[BLOCK] 192.168.1.20 -> ads.example (blocklist)")
        );
    }

    #[test]
    fn query_log_line_formats_pass_actions_without_reason() {
        let mut domain_map = test_map();
        domain_map.put(1, "ok.example".to_string());
        for (action, tag) in [
            (StatAction::Allowed, "ALLOW"),
            (StatAction::Proxied, "PROXY"),
            (StatAction::AllowedWithOverride, "OVERRIDE"),
        ] {
            let event = event_from([10, 0, 0, 1], 1, action);
            let line = query_log_line(&event, &mut domain_map, QueryLogLevel::All);
            assert_eq!(line, Some(format!("[{tag}] 10.0.0.1 -> ok.example")));
        }
    }

    #[test]
    fn query_log_line_cache_hits_are_logged_at_all_level() {
        let mut domain_map = test_map();
        domain_map.put(1, "cached.example".to_string());
        let event = event_from([10, 0, 0, 1], 1, StatAction::Cached);
        assert_eq!(
            query_log_line(&event, &mut domain_map, QueryLogLevel::All).as_deref(),
            Some("[CACHE] 10.0.0.1 -> cached.example")
        );
        assert!(query_log_line(&event, &mut domain_map, QueryLogLevel::Blocked).is_none());
    }

    #[test]
    fn query_log_line_servfails_are_logged_with_blocks() {
        let mut domain_map = test_map();
        domain_map.put(1, "broken.example".to_string());
        for (kind, cause) in [
            (StatError::Upstream, "upstream failure"),
            (StatError::DnssecBogus, "dnssec bogus"),
        ] {
            let event = event_from([10, 0, 0, 1], 1, StatAction::Error(kind));
            assert_eq!(
                query_log_line(&event, &mut domain_map, QueryLogLevel::Blocked),
                Some(format!("[SERVFAIL] 10.0.0.1 -> broken.example ({cause})"))
            );
            assert!(query_log_line(&event, &mut domain_map, QueryLogLevel::Off).is_none());
        }
    }

    #[test]
    fn summary_counts_errors_and_cache_hits() {
        let mut summary = TrafficSummary::default();
        for action in [
            StatAction::Cached,
            StatAction::Cached,
            StatAction::Error(StatError::Upstream),
            StatAction::Error(StatError::DnssecBogus),
        ] {
            summary.record(&event_from([10, 0, 0, 1], 1, action));
        }
        let line = summary.take_line(60, &test_map());
        assert!(line.contains("queries=4 blocked=0"), "{line}");
        assert!(line.contains("errors=2"), "{line}");
    }

    #[test]
    fn query_log_line_unknown_domain_falls_back() {
        let mut domain_map = test_map();
        let event = event_from([10, 0, 0, 1], 404, blocked());
        let line = query_log_line(&event, &mut domain_map, QueryLogLevel::All).unwrap();
        assert!(line.contains("<unknown>"), "{line}");
    }

    #[test]
    fn query_log_line_respects_cumulative_levels() {
        let mut domain_map = test_map();
        let suspicious = StatAction::Suspicious(StatBlockReason::LEXICAL_ANALYSIS);
        let highly = StatAction::HighlySuspicious(StatBlockReason::HIGH_ENTROPY);

        // (action, lowest level that prints it)
        let cases = [
            (suspicious, QueryLogLevel::Suspicious),
            (highly, QueryLogLevel::Suspicious),
            (blocked(), QueryLogLevel::Blocked),
            (StatAction::Allowed, QueryLogLevel::All),
            (StatAction::Proxied, QueryLogLevel::All),
            (StatAction::AllowedWithOverride, QueryLogLevel::All),
        ];
        let levels = [
            QueryLogLevel::Off,
            QueryLogLevel::Suspicious,
            QueryLogLevel::Blocked,
            QueryLogLevel::All,
        ];
        for (action, min_level) in cases {
            for level in levels {
                let event = event_from([10, 0, 0, 1], 1, action);
                let printed = query_log_line(&event, &mut domain_map, level).is_some();
                assert_eq!(printed, level >= min_level, "{action:?} at level {level:?}");
            }
        }
    }

    #[test]
    fn query_log_line_tags_suspicious_levels() {
        let mut domain_map = test_map();
        let high = event_from(
            [10, 0, 0, 1],
            1,
            StatAction::HighlySuspicious(StatBlockReason::HIGH_ENTROPY),
        );
        let low = event_from(
            [10, 0, 0, 1],
            1,
            StatAction::Suspicious(StatBlockReason::HIGH_ENTROPY),
        );
        let high_line = query_log_line(&high, &mut domain_map, QueryLogLevel::All).unwrap();
        let low_line = query_log_line(&low, &mut domain_map, QueryLogLevel::All).unwrap();
        assert!(high_line.starts_with("[SUSPICIOUS:HIGH] "), "{high_line}");
        assert!(low_line.starts_with("[SUSPICIOUS] "), "{low_line}");
        assert!(low_line.ends_with("(dga)"), "{low_line}");
    }

    // ── TrafficSummary ───────────────────────────────────────────────────────

    #[test]
    fn summary_empty_window() {
        let mut summary = TrafficSummary::default();
        assert_eq!(
            summary.take_line(900, &test_map()),
            "[SUMMARY] last 900s: queries=0 blocked=0 (0.0%) suspicious=0 errors=0 clients=0"
        );
    }

    #[test]
    fn summary_counts_and_top_blocked() {
        let mut domain_map = test_map();
        domain_map.put(1, "ads.example".to_string());
        domain_map.put(2, "tracker.example".to_string());

        let mut summary = TrafficSummary::default();
        for _ in 0..3 {
            summary.record(&event_from([10, 0, 0, 1], 1, blocked()));
        }
        summary.record(&event_from([10, 0, 0, 2], 2, blocked()));
        summary.record(&event_from(
            [10, 0, 0, 2],
            3,
            StatAction::Suspicious(StatBlockReason::HIGH_ENTROPY),
        ));
        summary.record(&event_from(
            [10, 0, 0, 3],
            4,
            StatAction::HighlySuspicious(StatBlockReason::HIGH_ENTROPY),
        ));
        for _ in 0..2 {
            summary.record(&event_from([10, 0, 0, 3], 5, StatAction::Proxied));
        }

        assert_eq!(
            summary.take_line(60, &domain_map),
            "[SUMMARY] last 60s: queries=8 blocked=4 (50.0%) suspicious=2 errors=0 clients=3 \
             top_blocked=ads.example (3)"
        );
    }

    #[test]
    fn summary_resets_after_take() {
        let mut summary = TrafficSummary::default();
        summary.record(&event_from([10, 0, 0, 1], 1, blocked()));
        let _ = summary.take_line(60, &test_map());

        let line = summary.take_line(60, &test_map());
        assert!(line.contains("queries=0 blocked=0"), "{line}");
        assert!(!line.contains("top_blocked"), "{line}");
    }

    #[test]
    fn summary_top_blocked_unknown_when_mapping_evicted() {
        let mut summary = TrafficSummary::default();
        summary.record(&event_from([10, 0, 0, 1], 99, blocked()));
        let line = summary.take_line(60, &test_map());
        assert!(line.ends_with("top_blocked=<unknown> (1)"), "{line}");
    }

    #[test]
    fn summary_tracking_is_capped() {
        let mut summary = TrafficSummary::default();
        let total = SUMMARY_TRACK_CAP as u32 + 10;
        for index in 0..total {
            let client = index.to_be_bytes();
            summary.record(&event_from(client, u64::from(index), blocked()));
        }
        // A domain first seen after the cap is reached is not tracked …
        summary.record(&event_from([1, 2, 3, 4], u64::from(total + 1), blocked()));
        assert_eq!(summary.blocked_domains.len(), SUMMARY_TRACK_CAP);
        assert!(!summary.blocked_domains.contains_key(&u64::from(total + 1)));
        // … but an already-tracked one keeps counting.
        summary.record(&event_from([1, 2, 3, 4], 0, blocked()));
        assert_eq!(summary.blocked_domains[&0], 2);
        assert_eq!(summary.clients.len(), SUMMARY_TRACK_CAP);

        let line = summary.take_line(60, &test_map());
        assert!(
            line.contains(&format!("blocked={}", total + 2)),
            "counters are not capped: {line}"
        );
        assert!(
            line.contains(&format!("clients={SUMMARY_TRACK_CAP}+")),
            "{line}"
        );
    }

    #[tokio::test]
    async fn process_event_feeds_summary() {
        let mut domain_map = test_map();
        let mut clients = Vec::new();
        let mut query_log = QueryLog::new(QueryLogLevel::Off);

        let msg = StatMessage::Event(event_from([10, 0, 0, 1], 1, blocked()));
        process_stat_message(&msg, &mut domain_map, &mut clients, &mut query_log).await;
        let mapping = StatMessage::DomainMapping {
            hash: 1,
            domain: "ads.example".to_string(),
        };
        process_stat_message(&mapping, &mut domain_map, &mut clients, &mut query_log).await;

        let line = query_log.summary.take_line(60, &domain_map);
        assert!(line.contains("queries=1 blocked=1"), "{line}");
        assert!(line.ends_with("top_blocked=ads.example (1)"), "{line}");
    }

    #[tokio::test]
    async fn every_event_refreshes_its_mapping() {
        // with logging off, events used to leave the LRU order
        // untouched, so busy domains were evicted like one-off ones and
        // then shown as <unknown>.
        let mut domain_map = LruCache::new(NonZeroUsize::new(2).unwrap());
        let mut clients = Vec::new();
        let mut query_log = QueryLog::new(QueryLogLevel::Off);
        for (hash, domain) in [(1u64, "busy.example"), (2, "idle.example")] {
            let mapping = StatMessage::DomainMapping {
                hash,
                domain: domain.to_string(),
            };
            process_stat_message(&mapping, &mut domain_map, &mut clients, &mut query_log).await;
        }
        let event = StatMessage::Event(event_from([10, 0, 0, 1], 1, StatAction::Allowed));
        process_stat_message(&event, &mut domain_map, &mut clients, &mut query_log).await;
        let newcomer = StatMessage::DomainMapping {
            hash: 3,
            domain: "new.example".to_string(),
        };
        process_stat_message(&newcomer, &mut domain_map, &mut clients, &mut query_log).await;

        assert!(domain_map.contains(&1), "busy domain kept");
        assert!(!domain_map.contains(&2), "idle domain evicted");
    }

    #[tokio::test]
    async fn process_domain_mapping_populates_map() {
        let mut domain_map = test_map();
        let mut clients = Vec::new();

        let msg = StatMessage::DomainMapping {
            hash: 42,
            domain: "example.com".to_string(),
        };
        process_stat_message(&msg, &mut domain_map, &mut clients, &mut test_log()).await;

        assert_eq!(domain_map.get(&42), Some(&"example.com".to_string()));
        assert!(clients.is_empty());
    }

    #[tokio::test]
    async fn process_event_uses_domain_map_for_lookup() {
        let mut domain_map = test_map();
        domain_map.put(99u64, "blocked.example".to_string());
        let mut clients = Vec::new();

        let event = StatEvent {
            timestamp: 0,
            domain_hash: 99,
            client_ip: std::net::Ipv4Addr::new(10, 0, 0, 1)
                .to_ipv6_mapped()
                .octets(),
            action: StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST),
        };
        let msg = StatMessage::Event(event);
        // Should not panic even though there are no socket clients
        process_stat_message(&msg, &mut domain_map, &mut clients, &mut test_log()).await;
    }

    #[tokio::test]
    async fn process_event_unknown_domain_does_not_panic() {
        let mut domain_map = test_map();
        let mut clients = Vec::new();

        let event = StatEvent {
            timestamp: 0,
            domain_hash: 9999, // not in domain_map
            client_ip: [0u8; 16],
            action: StatAction::Allowed,
        };
        process_stat_message(
            &StatMessage::Event(event),
            &mut domain_map,
            &mut clients,
            &mut test_log(),
        )
        .await;
    }

    #[tokio::test]
    async fn domain_map_evicts_oldest_when_full() {
        let cap = 4usize;
        let mut domain_map: LruCache<u64, String> = LruCache::new(NonZeroUsize::new(cap).unwrap());
        let mut clients = Vec::new();

        for i in 0..=(cap as u64) {
            let msg = StatMessage::DomainMapping {
                hash: i,
                domain: format!("d{i}.example"),
            };
            process_stat_message(&msg, &mut domain_map, &mut clients, &mut test_log()).await;
        }

        assert_eq!(domain_map.len(), cap, "map must not exceed capacity");
        // hash 0 was inserted first and never accessed — must have been evicted
        assert!(
            domain_map.peek(&0).is_none(),
            "oldest entry should be evicted"
        );
        // most-recently inserted entry must still be present
        assert!(domain_map.peek(&(cap as u64)).is_some());
    }

    // ── setup_unix_socket ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn setup_unix_socket_empty_path_returns_error() {
        let result = setup_unix_socket("").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn setup_unix_socket_valid_path_creates_listener() {
        let path = format!("/tmp/dgaard_test_sock_{}", std::process::id());
        let result = setup_unix_socket(&path).await;
        assert!(result.is_ok(), "Should create listener: {:?}", result.err());
        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    fn socket_path(dir: &tempfile::TempDir) -> String {
        dir.path().join("stats.sock").to_str().unwrap().to_owned()
    }

    #[tokio::test]
    async fn setup_unix_socket_is_owner_and_group_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(&dir);
        let _listener = setup_unix_socket(&path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_MODE, "got {mode:o}");
        // No staging file left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn setup_unix_socket_replaces_a_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(&dir);
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap()); // leaves the file
        let _listener = setup_unix_socket(&path).await.unwrap();
        // The fresh socket is the one listening at the path.
        tokio::net::UnixStream::connect(&path)
            .await
            .expect("connect to the new socket");
    }

    #[tokio::test]
    async fn setup_unix_socket_refuses_to_delete_other_files() {
        // Any file at the configured path used to be removed,
        // with the daemon often running as root.
        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(&dir);
        std::fs::write(&path, b"precious").unwrap();
        let err = setup_unix_socket(&path).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"precious");

        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"keep").unwrap();
        let link = dir.path().join("link.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(setup_unix_socket(link.to_str().unwrap()).await.is_err());
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    #[tokio::test]
    async fn setup_unix_socket_creates_the_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/dgaard/stats.sock");
        let _listener = setup_unix_socket(path.to_str().unwrap()).await.unwrap();
        assert!(path.exists());
    }

    // ── per-client writer tasks ──────────────────────────────────────────────

    async fn read_exactly(stream: &mut tokio::net::UnixStream, len: usize) -> Vec<u8> {
        use tokio::io::AsyncReadExt;

        let mut buf = vec![0u8; len];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
            .await
            .expect("data within 2 s")
            .unwrap();
        buf
    }

    #[tokio::test]
    async fn new_client_gets_the_snapshot_then_the_stream() {
        let (server_side, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let mut map = test_map();
        map.put(1, "one.example".to_string());
        let snapshot = domain_mappings_snapshot(&map);
        let client = StatsClient::spawn(server_side, snapshot.clone(), 8, Duration::from_secs(1));

        let first: Arc<[u8]> = Arc::from(&b"first"[..]);
        let second: Arc<[u8]> = Arc::from(&b"second"[..]);
        assert!(client.offer(&first));
        assert!(client.offer(&second));

        let expected = [snapshot.as_slice(), b"first", b"second"].concat();
        assert_eq!(read_exactly(&mut peer, expected.len()).await, expected);
    }

    #[tokio::test]
    async fn stuck_client_is_dropped_without_blocking_the_collector() {
        // A client that connects and never reads: its snapshot write blocks,
        // its queue fills, and the collector must neither wait nor keep it.
        let (server_side, _never_read) = tokio::net::UnixStream::pair().unwrap();
        let big_snapshot = vec![0u8; 4 * 1024 * 1024];
        let stuck = StatsClient::spawn(server_side, big_snapshot, 4, Duration::from_secs(30));
        let mut clients = vec![stuck];
        let mut domain_map = test_map();
        let mut query_log = QueryLog::new(QueryLogLevel::Off);

        let started = std::time::Instant::now();
        for hash in 0..20u64 {
            let msg = StatMessage::Event(event_from([10, 0, 0, 1], hash, StatAction::Allowed));
            process_stat_message(&msg, &mut domain_map, &mut clients, &mut query_log).await;
        }
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "collector stalled"
        );
        assert!(clients.is_empty(), "the stuck client was disconnected");
    }

    #[tokio::test]
    async fn stalled_writes_end_the_client_after_the_timeout() {
        let (server_side, _never_read) = tokio::net::UnixStream::pair().unwrap();
        let client = StatsClient::spawn(
            server_side,
            vec![0u8; 4 * 1024 * 1024],
            CLIENT_QUEUE,
            Duration::from_millis(50),
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while !client.tx.is_closed() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("writer task gave up after its write timeout");
        assert!(!client.offer(&Arc::from(&b"late"[..])));
    }

    #[tokio::test]
    async fn healthy_client_receives_broadcast_events() {
        let (server_side, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let mut clients = vec![StatsClient::spawn(
            server_side,
            Vec::new(),
            CLIENT_QUEUE,
            CLIENT_WRITE_TIMEOUT,
        )];
        let mut domain_map = test_map();
        let msg = StatMessage::Event(event_from([10, 0, 0, 1], 7, StatAction::Allowed));
        process_stat_message(&msg, &mut domain_map, &mut clients, &mut test_log()).await;
        let expected = msg.serialize();
        assert_eq!(read_exactly(&mut peer, expected.len()).await, expected);
        assert_eq!(clients.len(), 1);
    }
}
