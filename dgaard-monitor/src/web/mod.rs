mod routes;
pub mod state;

use std::net::IpAddr;
use std::sync::Arc;

use axum::Router;
use tokio::sync::{broadcast, watch};

use crate::config::WebConfig;
use crate::state::AppState;
use crate::util::{event_to_record, flags_of};
pub use state::{ClientStats, WebState};

fn bytes_to_ip(bytes: &[u8; 16]) -> IpAddr {
    if bytes[4..].iter().all(|&b| b == 0) {
        IpAddr::V4(std::net::Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::from(*bytes))
    }
}

async fn run_ingestor(app: Arc<AppState>, web: Arc<WebState>) {
    let mut rx = app.subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => {
                let domain_map = app.domain_map.read().await;
                let record = event_to_record(&event, &domain_map);
                drop(domain_map);

                let ip = bytes_to_ip(&event.client_ip);
                let is_blocked = flags_of(&event.action).is_some();
                let ts = event.timestamp;
                web.client_stats
                    .entry(ip)
                    .and_modify(|s| {
                        s.count += 1;
                        if is_blocked {
                            s.blocked += 1;
                        }
                        s.last_seen = ts;
                    })
                    .or_insert(ClientStats {
                        count: 1,
                        blocked: if is_blocked { 1 } else { 0 },
                        first_seen: ts,
                        last_seen: ts,
                    });

                web.push_event(record).await;
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                eprintln!("web ingestor: lagged by {n} events, some events lost");
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

pub async fn start(
    app: Arc<AppState>,
    web: Arc<WebState>,
    config: WebConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    let ingestor = {
        let app = Arc::clone(&app);
        let web = Arc::clone(&web);
        tokio::spawn(async move { run_ingestor(app, web).await })
    };

    let addr = format!("{}:{}", config.listen, config.port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("web server: failed to bind {addr}: {e}");
            ingestor.abort();
            return;
        }
    };

    println!("Web UI listening on http://{addr}");

    // Phase 2 will populate this router with static assets and API routes.
    let router = Router::new();
    let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
        let _ = shutdown.changed().await;
    });

    if let Err(e) = serve.await {
        eprintln!("web server error: {e}");
    }

    ingestor.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_ip_ipv4() {
        let bytes = [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            bytes_to_ip(&bytes),
            IpAddr::V4("192.168.1.1".parse().unwrap())
        );
    }

    #[test]
    fn bytes_to_ip_zero_is_ipv4() {
        let bytes = [0u8; 16];
        assert!(bytes_to_ip(&bytes).is_ipv4());
    }

    #[test]
    fn bytes_to_ip_ipv6_when_upper_bytes_nonzero() {
        let mut bytes = [0u8; 16];
        bytes[0] = 0x20;
        bytes[1] = 0x01;
        bytes[15] = 1;
        assert!(bytes_to_ip(&bytes).is_ipv6());
    }
}
