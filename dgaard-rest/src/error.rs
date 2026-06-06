use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Centralised error type for all dgaard-rest route handlers.
///
/// Every variant serialises to `{"error": "<message>"}` with the matching
/// HTTP status code, ensuring a consistent error envelope across all endpoints.
#[derive(Debug)]
pub enum ApiError {
    /// HTTP 400 Bad Request — missing or semantically invalid input.
    BadRequest(&'static str),
    /// HTTP 422 Unprocessable Entity — structurally valid but out-of-range input.
    UnprocessableEntity(&'static str),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::UnprocessableEntity(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
        };
        (status, Json(serde_json::json!({"error": msg}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_json(resp: Response) -> serde_json::Value {
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn bad_request_returns_400_and_error_json() {
        let resp = ApiError::BadRequest("missing or empty domain").into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "missing or empty domain");
    }

    #[tokio::test]
    async fn unprocessable_entity_returns_422_and_error_json() {
        let resp = ApiError::UnprocessableEntity("domain exceeds 253 characters").into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "domain exceeds 253 characters");
    }

    #[tokio::test]
    async fn error_body_has_only_error_key() {
        let resp = ApiError::BadRequest("test").into_response();
        let json = body_json(resp).await;
        assert!(json.is_object());
        assert_eq!(json.as_object().unwrap().len(), 1);
        assert!(json.get("error").is_some());
    }
}
