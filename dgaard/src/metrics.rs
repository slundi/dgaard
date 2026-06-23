use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    time::timeout,
};

use crate::STATS_COUNTERS;

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

fn render() -> String {
    let total = STATS_COUNTERS.queries_total.load(Ordering::Relaxed);
    let blocked = STATS_COUNTERS.queries_blocked.load(Ordering::Relaxed);
    let allowed = STATS_COUNTERS.queries_allowed.load(Ordering::Relaxed);
    let proxied = STATS_COUNTERS.queries_proxied.load(Ordering::Relaxed);
    let cached = STATS_COUNTERS.queries_cached.load(Ordering::Relaxed);
    let upstream_errors = STATS_COUNTERS
        .queries_upstream_errors
        .load(Ordering::Relaxed);
    let dropped = STATS_COUNTERS.stats_events_dropped.load(Ordering::Relaxed);

    format!(
        "# HELP dgaard_queries_total Total DNS queries received\n\
         # TYPE dgaard_queries_total counter\n\
         dgaard_queries_total {total}\n\
         # HELP dgaard_queries_blocked DNS queries blocked by filters\n\
         # TYPE dgaard_queries_blocked counter\n\
         dgaard_queries_blocked {blocked}\n\
         # HELP dgaard_queries_allowed DNS queries allowed through\n\
         # TYPE dgaard_queries_allowed counter\n\
         dgaard_queries_allowed {allowed}\n\
         # HELP dgaard_queries_proxied DNS queries proxied to upstream\n\
         # TYPE dgaard_queries_proxied counter\n\
         dgaard_queries_proxied {proxied}\n\
         # HELP dgaard_queries_cached DNS queries served from the response cache\n\
         # TYPE dgaard_queries_cached counter\n\
         dgaard_queries_cached {cached}\n\
         # HELP dgaard_queries_upstream_errors Queries that failed to forward to any upstream (returned SERVFAIL)\n\
         # TYPE dgaard_queries_upstream_errors counter\n\
         dgaard_queries_upstream_errors {upstream_errors}\n\
         # HELP dgaard_stats_events_dropped Telemetry events dropped due to stats channel backpressure\n\
         # TYPE dgaard_stats_events_dropped counter\n\
         dgaard_stats_events_dropped {dropped}\n"
    )
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
