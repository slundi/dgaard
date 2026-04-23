use async_trait::async_trait;
use rust_mcp_sdk::{
    auth::{AuthInfo, AuthProvider, AuthenticationError, OauthEndpoint},
    mcp_http::{self, GenericBody, GenericBodyExt, McpAppState},
    mcp_server::error::TransportServerError,
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// Simple static-token auth provider. Validates `Authorization: Bearer <token>` requests
/// against a single pre-shared token read from `McpConfig.auth_token`.
pub struct ConfigTokenAuthProvider {
    token: String,
}

impl ConfigTokenAuthProvider {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

/// How far into the future we set the synthetic expiry for a valid static token.
/// The auth middleware requires `expires_at` to be `Some(...)` and in the future.
const TOKEN_TTL: Duration = Duration::from_secs(365 * 24 * 3600); // 1 year

#[async_trait]
impl AuthProvider for ConfigTokenAuthProvider {
    async fn verify_token(&self, access_token: String) -> Result<AuthInfo, AuthenticationError> {
        if access_token == self.token {
            Ok(AuthInfo {
                token_unique_id: access_token,
                client_id: None,
                user_id: None,
                scopes: None,
                expires_at: Some(SystemTime::now() + TOKEN_TTL),
                audience: None,
                extra: None,
            })
        } else {
            Err(AuthenticationError::InvalidOrExpiredToken(
                "invalid token".into(),
            ))
        }
    }

    /// No OAuth endpoints — pure bearer-token validation only.
    fn auth_endpoints(&self) -> Option<&HashMap<String, OauthEndpoint>> {
        None
    }

    /// No OAuth metadata URL for a simple static token scheme.
    fn protected_resource_metadata_url(&self) -> Option<&str> {
        None
    }

    /// Never called when `auth_endpoints()` returns `None`.
    async fn handle_request(
        &self,
        _request: mcp_http::http::Request<&str>,
        _state: Arc<McpAppState>,
    ) -> Result<mcp_http::http::Response<GenericBody>, TransportServerError> {
        Ok(GenericBody::create_404_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(token: &str) -> ConfigTokenAuthProvider {
        ConfigTokenAuthProvider::new(token)
    }

    // ── verify_token ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_token_returns_auth_info() {
        let p = provider("secret");
        let info = p.verify_token("secret".into()).await.unwrap();
        assert_eq!(info.token_unique_id, "secret");
        assert!(info.expires_at.is_some());
        assert!(info.expires_at.unwrap() > SystemTime::now());
    }

    #[tokio::test]
    async fn invalid_token_returns_error() {
        let p = provider("secret");
        let err = p.verify_token("wrong".into()).await.unwrap_err();
        assert!(
            matches!(err, AuthenticationError::InvalidOrExpiredToken(_)),
            "expected InvalidOrExpiredToken, got {err:?}"
        );
    }

    #[tokio::test]
    async fn empty_token_is_rejected() {
        let p = provider("secret");
        assert!(p.verify_token(String::new()).await.is_err());
    }

    #[tokio::test]
    async fn empty_configured_token_accepts_empty_bearer() {
        // Edge-case: if the admin accidentally sets an empty token the provider
        // should still behave consistently (accept exact match).
        let p = provider("");
        assert!(p.verify_token(String::new()).await.is_ok());
    }

    // ── other trait methods ───────────────────────────────────────────────────

    #[test]
    fn auth_endpoints_is_none() {
        assert!(provider("t").auth_endpoints().is_none());
    }

    #[test]
    fn protected_resource_metadata_url_is_none() {
        assert!(provider("t").protected_resource_metadata_url().is_none());
    }

    #[test]
    fn required_scopes_is_none() {
        assert!(provider("t").required_scopes().is_none());
    }
}
