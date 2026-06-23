use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use crate::web::WebState;

const TICKET_TTL: Duration = Duration::from_secs(30);

/// Hard cap on the number of unconsumed tickets. A noisy authenticated
/// client could otherwise grow the map between purge cycles until expiry
/// catches up. 4 096 outstanding tickets is well above any realistic
/// browser concurrency and keeps the map's memory footprint trivial.
const MAX_TICKETS: usize = 4096;

pub async fn ws_ticket_handler(State(web): State<Arc<WebState>>) -> axum::response::Response {
    let now = Instant::now();
    // Purge expired tickets on every issue to prevent unbounded accumulation
    // if tickets are requested but never consumed.
    web.ws_tickets.retain(|_, expiry| *expiry > now);

    if web.ws_tickets.len() >= MAX_TICKETS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "too many outstanding ws tickets" })),
        )
            .into_response();
    }

    let ticket = match generate_ticket() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ws-ticket: entropy source unavailable: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "ticket generation failed" })),
            )
                .into_response();
        }
    };
    web.ws_tickets.insert(ticket.clone(), now + TICKET_TTL);

    (StatusCode::OK, Json(json!({ "ticket": ticket }))).into_response()
}

fn generate_ticket() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn generate_ticket_is_64_hex_chars() {
        let t = generate_ticket().unwrap();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_ticket_is_different_each_time() {
        assert_ne!(generate_ticket().unwrap(), generate_ticket().unwrap());
    }

    fn make_state() -> Arc<WebState> {
        let app = Arc::new(AppState::new(Duration::from_secs(3600)));
        Arc::new(WebState::new(app, 100))
    }

    #[tokio::test]
    async fn ticket_pool_exhaustion_returns_503() {
        let state = make_state();
        // Pre-fill the map to capacity with unexpired tickets.
        let far_future = Instant::now() + Duration::from_secs(3600);
        for i in 0..MAX_TICKETS {
            state.ws_tickets.insert(format!("ticket-{i}"), far_future);
        }
        let router = axum::Router::new()
            .route("/ws-ticket", axum::routing::post(ws_ticket_handler))
            .with_state(state);
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/ws-ticket")
                    .method("POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = resp.into_body().collect().await;
    }

    #[tokio::test]
    async fn successful_ticket_issue_returns_200_with_hex_ticket() {
        let state = make_state();
        let router = axum::Router::new()
            .route("/ws-ticket", axum::routing::post(ws_ticket_handler))
            .with_state(state.clone());
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/ws-ticket")
                    .method("POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ticket = v["ticket"].as_str().unwrap();
        assert_eq!(ticket.len(), 64);
        assert!(state.ws_tickets.contains_key(ticket));
    }
}
