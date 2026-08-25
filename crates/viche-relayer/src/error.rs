//! Relayer error types.
//!
//! Every failure mode that can escape the Axum handler layer lives here,
//! converted into an HTTP response via `axum::response::IntoResponse`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// The JSON body returned on 4xx/5xx errors.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
}

/// Errors that escape to the HTTP layer.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// The vote request payload failed structural validation.
    #[error("{0}")]
    Validation(String),

    /// The contract call was simulated but the on-chain logic reverted.
    #[error("on-chain revert: {0}")]
    OnChainRevert(String),

    /// The RPC provider returned an error (network, timeout, etc.).
    #[error("provider error: {0}")]
    Provider(#[from] alloy::transports::TransportError),

    /// The alloy contract call returned an error (build, encode, decode, send).
    #[error("contract error: {0}")]
    Contract(#[from] alloy::contract::Error),

    /// Deserialization / serialisation failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Missing or incorrect `Authorization` header on an `/api/admin/*` route.
    ///
    /// Deliberately carries no detail (never "key missing" vs "key wrong") so
    /// the response itself can't be used to probe the auth mechanism.
    #[error("missing or invalid admin api key")]
    Unauthorized,
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR"),
            Self::OnChainRevert(_) => (StatusCode::CONFLICT, "ON_CHAIN_REVERT"),
            Self::Provider(_) => (StatusCode::BAD_GATEWAY, "PROVIDER_ERROR"),
            Self::Contract(_) => (StatusCode::BAD_GATEWAY, "CONTRACT_ERROR"),
            Self::Json(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
        };
        let body = ApiError {
            code,
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

impl From<viche_core::wire::ValidationError> for RelayError {
    fn from(e: viche_core::wire::ValidationError) -> Self {
        Self::Validation(e.to_string())
    }
}
