use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use dgaard_monitor_core::service::ServiceError;

pub(crate) fn status_of(err: &ServiceError) -> StatusCode {
    match err {
        ServiceError::InvalidIp(_) | ServiceError::InvalidAction(_) => StatusCode::BAD_REQUEST,
        ServiceError::PersistenceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        ServiceError::Database(_) | ServiceError::Task(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Render a service error as `{"error": "<message>"}` with the matching status.
pub(crate) fn error_response(err: ServiceError) -> Response {
    (
        status_of(&err),
        Json(serde_json::json!({"error": err.to_string()})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dgaard_monitor_core::db::Database;

    #[test]
    fn client_errors_map_to_400() {
        assert_eq!(
            status_of(&ServiceError::InvalidIp("x".into())),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of(&ServiceError::InvalidAction("x".into())),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn missing_persistence_maps_to_503() {
        assert_eq!(
            status_of(&ServiceError::PersistenceUnavailable),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn database_error_maps_to_500() {
        let Err(db_err) = Database::open("/nonexistent-dir/monitor.sqlite", 1, 1) else {
            panic!("opening a database in a missing directory must fail");
        };
        let err = ServiceError::Database(db_err);
        assert_eq!(status_of(&err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn task_error_maps_to_500() {
        let join_err = tokio::spawn(async { panic!("boom") }).await.unwrap_err();
        assert_eq!(
            status_of(&ServiceError::Task(join_err)),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn response_body_carries_message() {
        let resp = error_response(ServiceError::PersistenceUnavailable);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["error"], "persistence not configured");
    }
}
