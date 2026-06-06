use axum::{Router, http::StatusCode, routing::get};

use crate::state::AppState;

/// GET /api/v1/health — liveness probe, returns 204 No Content.
async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/health", get(health))
}
