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

    /// The network's current gas price exceeds the configured ceiling, so the
    /// transaction was **not** broadcast. Transient by nature — a client that
    /// retries later will usually succeed.
    #[error("{0}")]
    GasPriceTooHigh(String),

    /// The submitter failed the configured registration eligibility gate.
    #[error("{0}")]
    NotEligible(String),

    /// A registration cap (per-source or per-batch) is already reached.
    #[error("{0}")]
    RegistrationCapReached(String),

    /// State that the caller was told would be saved could not be written to
    /// disk. Never reported as success — see [`crate::registration`].
    #[error("failed to persist state: {0}")]
    Persistence(String),
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
            // 503 rather than 4xx: nothing is wrong with the request, the
            // relayer is simply declining to spend at the current price.
            Self::GasPriceTooHigh(_) => (StatusCode::SERVICE_UNAVAILABLE, "GAS_PRICE_TOO_HIGH"),
            Self::NotEligible(_) => (StatusCode::FORBIDDEN, "NOT_ELIGIBLE"),
            Self::RegistrationCapReached(_) => {
                (StatusCode::TOO_MANY_REQUESTS, "REGISTRATION_CAP_REACHED")
            }
            Self::Persistence(_) => (StatusCode::INTERNAL_SERVER_ERROR, "PERSISTENCE_ERROR"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    fn status_of(err: RelayError) -> StatusCode {
        err.into_response().status()
    }

    #[test]
    fn gas_ceiling_rejections_are_retryable_503s() {
        assert_eq!(
            status_of(RelayError::GasPriceTooHigh("too pricey".into())),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn eligibility_failures_are_403_not_401() {
        // 401 would imply "authenticate and try again", which is wrong: the
        // gate is about who you are, not whether you proved it.
        assert_eq!(
            status_of(RelayError::NotEligible("nope".into())),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn registration_caps_report_429() {
        assert_eq!(
            status_of(RelayError::RegistrationCapReached("full".into())),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn persistence_failures_are_server_errors() {
        assert_eq!(
            status_of(RelayError::Persistence("disk on fire".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn preexisting_mappings_are_unchanged() {
        assert_eq!(
            status_of(RelayError::Validation("bad".into())),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of(RelayError::OnChainRevert("reverted".into())),
            StatusCode::CONFLICT
        );
        assert_eq!(status_of(RelayError::Unauthorized), StatusCode::UNAUTHORIZED);
    }
}
