use std::fmt::Write;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    time::timeout,
};

use crate::STATS_COUNTERS;
use crate::stats::StatsCounters;

/// Cap on how long a single metrics request line read may take. A slow-read
/// scanner that holds the connection open indefinitely is otherwise free
/// to exhaust tokio task slots.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Serve a Prometheus-compatible `/metrics` endpoint on `addr`.
///
/// Binds a TCP listener and responds to every HTTP request with the current
/// counter values in OpenMetrics text format.  The server stops accepting new
/// connections as soon as the shutdown watch fires.
pub async fn serve(addr: String, mut shutdown_rx: watch::Receiver<bool>) {
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("metrics: failed to bind {addr}: {e}");
            return;
        }
    };
    println!("Metrics endpoint listening on http://{addr}/metrics");
    if let Some(warning) = listener.local_addr().ok().and_then(exposure_warning) {
        eprintln!("{warning}");
    }

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
            result = listener.accept() => {
                match result {
                    Ok((mut stream, _)) => {
                        tokio::spawn(async move {
                            let mut buf = [0u8; 1024];
                            // Bound the read so a slow-loris scanner can't
                            // pin the connection open indefinitely.
                            let read_result = timeout(
                                REQUEST_READ_TIMEOUT,
                                stream.read(&mut buf),
                            )
                            .await;
                            let n = match read_result {
                                Ok(Ok(n)) => n,
                                _ => return,
                            };

                            let response = build_response(&buf[..n]);
                            let _ = stream.write_all(response.as_bytes()).await;
                        });
                    }
                    Err(e) => eprintln!("metrics: accept error: {e}"),
                }
            }
        }
    }
}

/// Build the HTTP response for a metrics request. Only `GET /metrics` is
/// accepted; everything else returns 404. The body is included only on the
/// happy path so that probes for `/`, `/foo`, etc. do not return counter
/// values.
fn build_response(request: &[u8]) -> String {
    let first_line = std::str::from_utf8(request)
        .unwrap_or("")
        .split("\r\n")
        .next()
        .unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method == "GET" && (path == "/metrics" || path.starts_with("/metrics?")) {
        let body = render();
        format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            body.len(),
            body,
        )
    } else {
        let body = "not found\n";
        format!(
            "HTTP/1.1 404 Not Found\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            body.len(),
            body,
        )
    }
}

/// Startup warning for an endpoint reachable from other hosts: it has no
/// authentication, and its counters reveal traffic volume and policy.
fn exposure_warning(local: SocketAddr) -> Option<String> {
    (!local.ip().is_loopback()).then(|| {
        format!(
            "warn: metrics endpoint on {local} is unauthenticated and reachable from other \
             hosts; bind it to 127.0.0.1 unless a firewall restricts access"
        )
    })
}

/// One exported counter: metric name, help text, and how to read it.
struct Counter {
    name: &'static str,
    help: &'static str,
    read: fn(&StatsCounters) -> u64,
}

/// Every counter in [`StatsCounters`]. The first seven keep their original
/// names for existing dashboards; later ones follow the Prometheus
/// `_total` convention, as named in `docs/Roadmap-recursive-DNS.md`.
const COUNTERS: &[Counter] = &[
    Counter {
        name: "dgaard_queries_total",
        help: "Total DNS queries received",
        read: StatsCounters::get_total,
    },
    Counter {
        name: "dgaard_queries_blocked",
        help: "DNS queries blocked by filters",
        read: StatsCounters::get_blocked,
    },
    Counter {
        name: "dgaard_queries_allowed",
        help: "DNS queries allowed through",
        read: StatsCounters::get_allowed,
    },
    Counter {
        name: "dgaard_queries_proxied",
        help: "DNS queries proxied to upstream",
        read: StatsCounters::get_proxied,
    },
    Counter {
        name: "dgaard_queries_cached",
        help: "DNS queries served from the response cache",
        read: StatsCounters::get_cached,
    },
    Counter {
        name: "dgaard_queries_upstream_errors",
        help: "Queries that failed to forward to any upstream (returned SERVFAIL)",
        read: StatsCounters::get_upstream_errors,
    },
    Counter {
        name: "dgaard_stats_events_dropped",
        help: "Telemetry events dropped due to stats channel backpressure",
        read: StatsCounters::get_stats_dropped,
    },
    Counter {
        name: "dgaard_recursive_queries_total",
        help: "Queries sent to authoritative servers by the recursive resolver",
        read: StatsCounters::get_recursive_queries,
    },
    Counter {
        name: "dgaard_recursive_referrals_total",
        help: "Referrals followed by the recursive resolver",
        read: StatsCounters::get_recursive_referrals,
    },
    Counter {
        name: "dgaard_recursive_glue_hit_total",
        help: "Referrals whose name server addresses came from in-bailiwick glue",
        read: StatsCounters::get_recursive_glue_hit,
    },
    Counter {
        name: "dgaard_recursive_glue_miss_total",
        help: "Referrals that needed a separate lookup of name server addresses",
        read: StatsCounters::get_recursive_glue_miss,
    },
    Counter {
        name: "dgaard_recursive_tcp_fallback_total",
        help: "Truncated UDP answers retried over TCP",
        read: StatsCounters::get_recursive_tcp_fallback,
    },
    Counter {
        name: "dgaard_recursive_cycle_detected_total",
        help: "Resolutions stopped on a delegation or CNAME cycle",
        read: StatsCounters::get_recursive_cycle_detected,
    },
    Counter {
        name: "dgaard_recursive_depth_cap_hit_total",
        help: "Resolutions stopped at the maximum delegation depth",
        read: StatsCounters::get_recursive_depth_cap_hit,
    },
    Counter {
        name: "dgaard_recursive_query_cap_hit_total",
        help: "Resolutions stopped at max_queries_per_resolution",
        read: StatsCounters::get_recursive_query_cap_hit,
    },
    Counter {
        name: "dgaard_recursive_bailiwick_reject_total",
        help: "Out-of-bailiwick referrals rejected",
        read: StatsCounters::get_recursive_bailiwick_reject,
    },
    Counter {
        name: "dgaard_recursive_dnssec_chain_built_total",
        help: "DNSSEC chains of trust verified up to the root",
        read: StatsCounters::get_recursive_dnssec_chain_built,
    },
    Counter {
        name: "dgaard_recursive_dnssec_chain_broken_total",
        help: "DNSSEC chain-of-trust checks that ended Bogus",
        read: StatsCounters::get_recursive_dnssec_chain_broken,
    },
    Counter {
        name: "dgaard_prefetch_dropped_total",
        help: "Prefetch requests dropped because the queue was full",
        read: StatsCounters::get_prefetch_dropped,
    },
    Counter {
        name: "dgaard_prefetch_completed_total",
        help: "Prefetch refreshes that succeeded",
        read: StatsCounters::get_prefetch_completed,
    },
    Counter {
        name: "dgaard_prefetch_failed_total",
        help: "Prefetch refreshes that failed",
        read: StatsCounters::get_prefetch_failed,
    },
];

fn render() -> String {
    render_counters(&STATS_COUNTERS)
}

fn render_counters(stats: &StatsCounters) -> String {
    let mut out = String::with_capacity(COUNTERS.len() * 160);
    for counter in COUNTERS {
        let _ = write!(
            out,
            "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n",
            name = counter.name,
            help = counter.help,
            value = (counter.read)(stats),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn render_contains_all_counters() {
        STATS_COUNTERS.queries_total.store(10, Ordering::Relaxed);
        STATS_COUNTERS.queries_blocked.store(2, Ordering::Relaxed);
        STATS_COUNTERS.queries_allowed.store(5, Ordering::Relaxed);
        STATS_COUNTERS.queries_proxied.store(3, Ordering::Relaxed);
        STATS_COUNTERS.queries_cached.store(4, Ordering::Relaxed);
        STATS_COUNTERS
            .queries_upstream_errors
            .store(11, Ordering::Relaxed);
        STATS_COUNTERS
            .stats_events_dropped
            .store(7, Ordering::Relaxed);

        let out = render();
        assert!(out.contains("dgaard_queries_total 10"));
        assert!(out.contains("dgaard_queries_blocked 2"));
        assert!(out.contains("dgaard_queries_allowed 5"));
        assert!(out.contains("dgaard_queries_proxied 3"));
        assert!(out.contains("dgaard_queries_cached 4"));
        assert!(out.contains("dgaard_queries_upstream_errors 11"));
        assert!(out.contains("dgaard_stats_events_dropped 7"));
    }

    #[test]
    fn render_includes_help_and_type_lines() {
        let out = render();
        assert!(out.contains("# HELP dgaard_queries_total"));
        assert!(out.contains("# TYPE dgaard_queries_total counter"));
        assert!(out.contains("# HELP dgaard_queries_blocked"));
        assert!(out.contains("# TYPE dgaard_queries_blocked counter"));
        assert!(out.contains("# HELP dgaard_queries_cached"));
        assert!(out.contains("# TYPE dgaard_queries_cached counter"));
        assert!(out.contains("# HELP dgaard_stats_events_dropped"));
        assert!(out.contains("# TYPE dgaard_stats_events_dropped counter"));
    }

    /// Every `AtomicU64` field of `StatsCounters`.
    fn every_field(stats: &StatsCounters) -> Vec<&std::sync::atomic::AtomicU64> {
        vec![
            &stats.queries_total,
            &stats.queries_blocked,
            &stats.queries_allowed,
            &stats.queries_proxied,
            &stats.queries_cached,
            &stats.queries_upstream_errors,
            &stats.stats_events_dropped,
            &stats.recursive_queries,
            &stats.recursive_referrals,
            &stats.recursive_glue_hit,
            &stats.recursive_glue_miss,
            &stats.recursive_tcp_fallback,
            &stats.recursive_cycle_detected,
            &stats.recursive_depth_cap_hit,
            &stats.recursive_query_cap_hit,
            &stats.recursive_bailiwick_reject,
            &stats.recursive_dnssec_chain_built,
            &stats.recursive_dnssec_chain_broken,
            &stats.prefetch_dropped,
            &stats.prefetch_completed,
            &stats.prefetch_failed,
        ]
    }

    #[test]
    fn render_exports_every_stats_counter() {
        // Recursive, prefetch and DNSSEC counters were never
        // exported. A distinct value per field proves each metric reads
        // its own counter.
        // StatsCounters holds only AtomicU64 fields: a counter added
        // without a metric changes its size and fails here.
        let field_count = std::mem::size_of::<StatsCounters>()
            / std::mem::size_of::<std::sync::atomic::AtomicU64>();
        assert_eq!(field_count, COUNTERS.len(), "a counter is not exported");

        let stats = StatsCounters::new();
        let fields = every_field(&stats);
        assert_eq!(fields.len(), field_count);
        for (index, field) in fields.iter().enumerate() {
            field.store(1000 + index as u64, Ordering::Relaxed);
        }

        let out = render_counters(&stats);
        let mut seen: Vec<u64> = out
            .lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.rsplit(' ').next().unwrap().parse().unwrap())
            .collect();
        seen.sort_unstable();
        let expected: Vec<u64> = (0..COUNTERS.len() as u64).map(|i| 1000 + i).collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn render_exports_recursive_prefetch_and_dnssec_counters() {
        let stats = StatsCounters::new();
        stats.increment_recursive_queries();
        stats.increment_recursive_dnssec_chain_broken();
        stats.increment_prefetch_completed();
        stats.increment_prefetch_completed();
        let out = render_counters(&stats);
        assert!(out.contains("\ndgaard_recursive_queries_total 1\n"));
        assert!(out.contains("\ndgaard_recursive_dnssec_chain_broken_total 1\n"));
        assert!(out.contains("\ndgaard_prefetch_completed_total 2\n"));
        assert!(out.contains("\ndgaard_prefetch_failed_total 0\n"));
    }

    #[test]
    fn every_metric_is_unique_and_documented() {
        let mut names: Vec<&str> = COUNTERS.iter().map(|counter| counter.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), COUNTERS.len(), "duplicate metric name");

        let out = render_counters(&StatsCounters::new());
        for counter in COUNTERS {
            assert!(counter.name.starts_with("dgaard_"), "{}", counter.name);
            assert!(!counter.help.is_empty(), "{}", counter.name);
            assert!(out.contains(&format!("# HELP {} ", counter.name)));
            assert!(out.contains(&format!("# TYPE {} counter\n", counter.name)));
        }
    }

    #[test]
    fn exposure_warning_only_for_non_loopback_addresses() {
        for local in ["127.0.0.1:9153", "[::1]:9153"] {
            assert!(
                exposure_warning(local.parse().unwrap()).is_none(),
                "{local}"
            );
        }
        for local in ["0.0.0.0:9153", "[::]:9153", "192.168.1.1:9153"] {
            let warning = exposure_warning(local.parse().unwrap()).expect(local);
            assert!(warning.contains("unauthenticated"), "{warning}");
            assert!(warning.contains("127.0.0.1"), "{warning}");
        }
    }

    #[test]
    fn render_ends_with_newline() {
        let out = render();
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn build_response_returns_200_for_get_metrics() {
        let resp = build_response(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("dgaard_queries_total"));
    }

    #[test]
    fn build_response_accepts_query_string_on_metrics() {
        let resp = build_response(b"GET /metrics?foo=bar HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
    }

    #[test]
    fn build_response_returns_404_for_root() {
        let resp = build_response(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"));
        assert!(!resp.contains("dgaard_queries_total"));
    }

    #[test]
    fn build_response_returns_404_for_post() {
        let resp = build_response(b"POST /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"));
    }

    #[test]
    fn build_response_returns_404_for_empty_request() {
        let resp = build_response(b"");
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"));
    }
}
