use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use crate::web::WebState;

const TICKET_TTL: Duration = Duration::from_secs(30);

pub async fn ws_ticket_handler(State(web): State<Arc<WebState>>) -> impl IntoResponse {
    let now = Instant::now();
    // Purge expired tickets on every issue to prevent unbounded accumulation
    // if tickets are requested but never consumed.
    web.ws_tickets.retain(|_, expiry| *expiry > now);

    let ticket = generate_ticket();
    web.ws_tickets.insert(ticket.clone(), now + TICKET_TTL);

    (StatusCode::OK, Json(json!({ "ticket": ticket })))
}

fn generate_ticket() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("getrandom: entropy source unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ticket_is_64_hex_chars() {
        let t = generate_ticket();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_ticket_is_different_each_time() {
        assert_ne!(generate_ticket(), generate_ticket());
    }
}
