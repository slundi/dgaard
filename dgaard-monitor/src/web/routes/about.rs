use axum::Json;
use serde_json::{Value, json};

pub async fn about_handler() -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "license": "Apache-2.0",
        "endpoints": [
            { "name": "WebSocket live feed", "path": "/ws" },
            { "name": "Stats",               "path": "GET /api/v1/stats" },
            { "name": "Queries",             "path": "GET /api/v1/queries" },
            { "name": "Talkers",             "path": "GET /api/v1/talkers" },
            { "name": "Timelines",           "path": "GET /api/v1/timelines" },
            { "name": "Lists",               "path": "GET /api/v1/lists" },
            { "name": "Health",              "path": "GET /api/v1/health" },
            { "name": "About",               "path": "GET /api/v1/about" },
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn about_contains_version() {
        let Json(body) = about_handler().await;
        assert!(!body["version"].as_str().unwrap_or("").is_empty());
    }

    #[tokio::test]
    async fn about_contains_license() {
        let Json(body) = about_handler().await;
        assert_eq!(body["license"].as_str().unwrap(), "Apache-2.0");
    }

    #[tokio::test]
    async fn about_contains_endpoints() {
        let Json(body) = about_handler().await;
        let eps = body["endpoints"].as_array().unwrap();
        assert!(!eps.is_empty());
        assert!(
            eps.iter()
                .any(|e| e["path"].as_str().unwrap_or("").contains("/ws"))
        );
    }
}
