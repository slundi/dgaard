mod blocklist;
mod check;
mod health;

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .merge(health::router())
        .merge(blocklist::router())
        .merge(check::router())
}
