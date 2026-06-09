mod routes;
pub mod state;

use std::net::IpAddr;
use std::sync::Arc;

use axum::{
    Router,
    extract::Path,
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use rust_embed::Embed;
use tokio::sync::{broadcast, watch};

use crate::config::WebConfig;
use crate::state::AppState;
use crate::util::{event_to_record, flags_of};
pub use state::{ClientStats, WebState};

// ── Static asset embedding ─────────────────────────────────────────────────

#[derive(Embed)]
#[folder = "assets/"]
struct Assets;

fn mime_for(name: &str) -> &'static str {
    if name.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if name.ends_with(".js") {
        "application/javascript"
    } else if name.ends_with(".css") {
        "text/css"
    } else {
        "application/octet-stream"
    }
}

fn serve_embedded(name: &str) -> Response {
    match Assets::get(name) {
        Some(content) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime_for(name))],
            content.data.into_owned(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve_index() -> Response {
    serve_embedded("index.html")
}

async fn serve_asset(Path(path): Path<String>) -> Response {
    serve_embedded(&path)
}

// ── Bearer auth middleware ─────────────────────────────────────────────────

async fn require_bearer(
    token: Arc<String>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if token.is_empty() {
        return next.run(request).await;
    }
    let bearer_ok = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == format!("Bearer {}", token.as_str()))
        .unwrap_or(false);
    // Browsers cannot set custom headers on WebSocket connections, so /ws also
    // accepts a ?token= query parameter.
    let query_ok = request.uri().path() == "/ws"
        && request
            .uri()
            .query()
            .and_then(|q| q.split('&').find(|p| p.starts_with("token=")))
            .map(|p| &p["token=".len()..] == token.as_str())
            .unwrap_or(false);
    if bearer_ok || query_ok {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response()
    }
}

// ── Router ─────────────────────────────────────────────────────────────────

fn build_router(web: Arc<WebState>, token: String) -> Router {
    let token = Arc::new(token);

    // Apply a single outer middleware that guards /api/v1/* and /ws.
    // Using one layer on the whole router avoids route-priority races
    // between the static-asset catch-all and nested protected routers.
    let auth_layer = {
        let token = Arc::clone(&token);
        axum::middleware::from_fn(move |req: axum::extract::Request, next: Next| {
            let token = Arc::clone(&token);
            async move {
                let needs_auth = {
                    let p = req.uri().path();
                    p.starts_with("/api/v1") || p == "/ws"
                };
                if needs_auth {
                    require_bearer(token, req, next).await
                } else {
                    next.run(req).await
                }
            }
        })
    };

    Router::new()
        .route("/", get(serve_index))
        .route("/{*path}", get(serve_asset))
        // /api/v1/* — Phases 5+ add routes to this nest
        .nest(
            "/api/v1",
            Router::new().fallback(|| async { StatusCode::NOT_FOUND }),
        )
        .route("/ws", get(routes::ws::ws_handler))
        .layer(auth_layer)
        .with_state(web)
}

// ── Ingestor task ──────────────────────────────────────────────────────────

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

// ── Server entry-point ─────────────────────────────────────────────────────

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

    let router = build_router(Arc::clone(&web), config.token);
    let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
        let _ = shutdown.changed().await;
    });

    if let Err(e) = serve.await {
        eprintln!("web server error: {e}");
    }

    ingestor.abort();
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use std::time::Duration;
    use tower::ServiceExt;

    fn make_web_state() -> Arc<WebState> {
        let app = Arc::new(AppState::new(Duration::from_secs(3600)));
        Arc::new(WebState::new(app, 100))
    }

    fn make_router(token: &str) -> Router {
        build_router(make_web_state(), token.to_string())
    }

    async fn body_string(body: Body) -> String {
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    // ── Static assets ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_index_returns_html() {
        let app = make_router("");
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert!(ct.to_str().unwrap().contains("text/html"));
    }

    #[tokio::test]
    async fn get_style_css_returns_css() {
        let app = make_router("");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/style.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert!(ct.to_str().unwrap().contains("text/css"));
    }

    #[tokio::test]
    async fn get_alpine_js_returns_js() {
        let app = make_router("");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/alpine.min.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert!(ct.to_str().unwrap().contains("javascript"));
    }

    #[tokio::test]
    async fn unknown_asset_returns_404() {
        let app = make_router("");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/nonexistent.xyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Auth middleware ────────────────────────────────────────────────────

    #[tokio::test]
    async fn api_no_token_configured_returns_404() {
        let app = make_router("");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Auth skipped (empty token) → no route → 404
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_missing_auth_header_returns_401() {
        let app = make_router("secret");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_string(resp.into_body()).await;
        assert!(body.contains("unauthorized"));
    }

    #[tokio::test]
    async fn api_wrong_token_returns_401() {
        let app = make_router("secret");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_correct_token_passes_auth() {
        let app = make_router("secret");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .header("authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Auth passed; no matching route → 404, not 401
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn ws_missing_auth_returns_401() {
        let app = make_router("secret");
        let resp = app
            .oneshot(Request::builder().uri("/ws").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ws_correct_query_token_passes_auth() {
        let app = make_router("secret");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ws?token=secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Auth passed; plain HTTP to WS endpoint → 400, not 401.
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ws_wrong_query_token_returns_401() {
        let app = make_router("secret");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ws?token=wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn static_assets_require_no_auth() {
        let app = make_router("secret");
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // Static index is public even with a token configured
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── IP helpers ─────────────────────────────────────────────────────────

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
