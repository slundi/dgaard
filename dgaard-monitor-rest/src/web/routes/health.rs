use axum::http::StatusCode;

pub async fn health_handler() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_returns_no_content() {
        let status = health_handler().await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
}
