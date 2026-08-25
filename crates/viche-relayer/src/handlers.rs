//! Axum HTTP handlers for the Viche relayer.
//!
//! Endpoints:
//!   - `GET  /health`            — liveness check (always 200).
//!   - `POST /api/vote`          — accept a ZK proof + vote, broadcast on-chain.
//!   - `GET  /api/polls`         — list all polls.
//!   - `GET  /api/polls/:id`     — fetch a single poll's metadata.
//!   - `GET  /api/polls/:id/tally` — fetch a poll's per-option tallies.
//!   - `POST /api/admin/polls`        — owner-only: create a poll.
//!   - `POST /api/admin/polls/:id/close` — owner-only: close a poll.
//!
//! The vote handler is a thin shim: parse → validate → relay → respond.
//! The poll handlers delegate to [`crate::queries`] for the chain reads.
//! The admin handlers require `Authorization: Bearer <ADMIN_API_KEY>` and
//! sign with a separate key from the vote-relay path — see
//! [`crate::config::Config::admin_private_key`].

use alloy::network::Ethereum;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::transports::Transport;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use viche_core::wire::{PollData, PollListResponse, TallyResponse, VoteRequest, VoteResponse};

use crate::error::RelayError;
use crate::queries::{fetch_all_polls, fetch_poll, fetch_tally};
use crate::relay::{submit_close_poll, submit_create_poll, submit_vote, AdminTxResponse};

/// Application state shared across all handlers via Axum's `State` extractor.
///
/// Holds the alloy providers (HTTP transport + wallet fillers, already
/// connected) and the on-chain `VotingManager` address. All read-only after
/// construction; `Clone` is cheap (the providers are internally `Arc`'d).
#[derive(Clone)]
pub struct AppState<P> {
    /// Signs `castVote` for the gasless voting path. No special on-chain
    /// privilege (`castVote` isn't access-controlled).
    pub provider: P,
    /// Signs `createPoll`/`closePoll`. Must be the `VotingManager` owner.
    pub admin_provider: P,
    pub voting_manager_address: Address,
    /// Shared secret required on `/api/admin/*` requests.
    pub admin_api_key: String,
}

/// Build the Axum router from the given state.
///
/// `P` must implement `Provider` over *some* transport `T` so the router is
/// agnostic to whether the underlying connection is reqwest, hyper, etc.
pub fn router<P, T>(state: AppState<P>) -> Router
where
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    T: Transport + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/health", get(health))
        .route("/api/vote", post(cast_vote::<P, T>))
        .route("/api/polls", get(list_polls::<P, T>))
        .route("/api/polls/:id", get(get_poll::<P, T>))
        .route("/api/polls/:id/tally", get(get_tally::<P, T>))
        .route("/api/admin/polls", post(create_poll::<P, T>))
        .route("/api/admin/polls/:id/close", post(close_poll::<P, T>))
        .with_state(state)
}

// =========================================================================
// Handlers
// =========================================================================

/// `GET /health`
///
/// Trivial liveness check. Returns 200 if the server is reachable.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

#[derive(Debug, serde::Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// `POST /api/vote`
///
/// Accept a JSON [`VoteRequest`], validate its structure, then broadcast the
/// `castVote` transaction on-chain via the relayer's funded EOA.
///
/// # Request
///
/// ```json
/// {
///   "poll_id": 1,
///   "vote_option": 2,
///   "nullifier_hash": "0x...",
///   "proof": "0x..."          // 256 bytes, abi-encoded (pA, pB, pC)
/// }
/// ```
///
/// # Response (200)
///
/// ```json
/// { "tx_hash": "0x...", "status": "broadcast" }
/// ```
///
/// # Errors (4xx / 5xx)
///
/// See [`RelayError`] for the error-to-status mapping.
async fn cast_vote<P, T>(
    State(state): State<AppState<P>>,
    Json(req): Json<VoteRequest>,
) -> Result<Json<VoteResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    // 1. Validate the request structure (proof length, field ranges).
    req.validate()?;

    tracing::info!(
        poll_id = %req.poll_id,
        vote_option = %req.vote_option,
        "validated vote request"
    );

    // 2. Broadcast the castVote transaction on-chain.
    let resp = submit_vote(
        state.provider,
        state.voting_manager_address,
        req.poll_id,
        &req.nullifier_hash,
        &req.proof,
        req.vote_option,
    )
    .await?;

    // 3. Respond with the tx hash.
    Ok(Json(resp))
}

/// `GET /api/polls`
///
/// Returns metadata for every poll on-chain (id 1..=nextPollId-1).
async fn list_polls<P, T>(
    State(state): State<AppState<P>>,
) -> Result<Json<PollListResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    let polls = fetch_all_polls(state.provider, state.voting_manager_address).await?;
    Ok(Json(PollListResponse { polls }))
}

/// `GET /api/polls/:id`
///
/// Returns a single poll's metadata. `:id` is a decimal `uint256`.
async fn get_poll<P, T>(
    State(state): State<AppState<P>>,
    Path(id): Path<String>,
) -> Result<Json<PollData>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    let poll_id = parse_poll_id(&id)?;
    let poll = fetch_poll(state.provider, state.voting_manager_address, poll_id).await?;
    Ok(Json(poll))
}

/// `GET /api/polls/:id/tally`
///
/// Returns the per-option tallies for a poll.
async fn get_tally<P, T>(
    State(state): State<AppState<P>>,
    Path(id): Path<String>,
) -> Result<Json<TallyResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    let poll_id = parse_poll_id(&id)?;
    let tally = fetch_tally(state.provider, state.voting_manager_address, poll_id).await?;
    Ok(Json(tally))
}

/// Request body for `POST /api/admin/polls`.
#[derive(Debug, serde::Deserialize)]
struct CreatePollRequest {
    /// Root of the Poseidon Merkle tree of eligible identity commitments,
    /// as a `0x`-prefixed 32-byte hex string.
    merkle_root: B256,
    /// Number of vote options (>= 2).
    num_options: U256,
    /// Unix timestamp after which voting is rejected.
    deadline: U256,
    /// Off-chain pointer (IPFS/HTTP) to the poll question / option labels.
    /// Not inspected on-chain.
    #[serde(default)]
    metadata_uri: String,
}

/// `POST /api/admin/polls`
///
/// Owner-only. Requires `Authorization: Bearer <ADMIN_API_KEY>`. Signs and
/// broadcasts `createPoll` with the admin key (see [`AppState::admin_provider`]).
///
/// # Request
///
/// ```json
/// {
///   "merkle_root": "0x1111111122222222333333334444444455555555666666667777777788888888",
///   "num_options": "2",
///   "deadline": "1893456000",
///   "metadata_uri": "ipfs://..."
/// }
/// ```
///
/// # Response (200)
///
/// ```json
/// { "tx_hash": "0x...", "status": "broadcast" }
/// ```
///
/// The assigned `pollId` isn't known synchronously (it's a return value only
/// observable once the tx is mined) — poll `GET /api/polls` to find it.
async fn create_poll<P, T>(
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Json(req): Json<CreatePollRequest>,
) -> Result<Json<AdminTxResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    require_admin_auth(&headers, &state.admin_api_key)?;
    validate_create_poll_request(&req)?;

    tracing::info!(
        num_options = %req.num_options,
        deadline = %req.deadline,
        "validated admin createPoll request"
    );

    let resp = submit_create_poll(
        state.admin_provider,
        state.voting_manager_address,
        req.merkle_root,
        req.num_options,
        req.deadline,
        req.metadata_uri,
    )
    .await?;

    Ok(Json(resp))
}

/// Pre-checks for [`CreatePollRequest`] that catch obviously-malformed
/// payloads before spending gas — the contract enforces the same rules
/// (`InvalidNumOptions`/`InvalidDeadline`) so this is belt-and-braces, not
/// the source of truth.
fn validate_create_poll_request(req: &CreatePollRequest) -> Result<(), RelayError> {
    if req.num_options < U256::from(2u64) {
        return Err(RelayError::Validation(
            "num_options must be at least 2".into(),
        ));
    }
    if req.deadline == U256::ZERO {
        return Err(RelayError::Validation(
            "deadline must be a non-zero unix timestamp".into(),
        ));
    }
    Ok(())
}

/// `POST /api/admin/polls/:id/close`
///
/// Owner-only. Requires `Authorization: Bearer <ADMIN_API_KEY>`. `:id` is a
/// decimal (or `0x`-hex) `uint256`, same format as `GET /api/polls/:id`.
async fn close_poll<P, T>(
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<AdminTxResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    require_admin_auth(&headers, &state.admin_api_key)?;
    let poll_id = parse_poll_id(&id)?;

    let resp =
        submit_close_poll(state.admin_provider, state.voting_manager_address, poll_id).await?;
    Ok(Json(resp))
}

/// Verify the `Authorization: Bearer <key>` header against `expected`.
///
/// Compares in constant time (relative to the header's length) so the
/// response timing can't be used to brute-force the shared secret one byte
/// at a time.
fn require_admin_auth(headers: &HeaderMap, expected: &str) -> Result<(), RelayError> {
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(key) if !key.is_empty() && constant_time_eq(key, expected) => Ok(()),
        _ => Err(RelayError::Unauthorized),
    }
}

/// Constant-time string comparison (length-independent short-circuit on a
/// length mismatch is fine — the secret's length isn't itself secret).
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Parse a poll-id path segment (decimal or 0x-hex) into a [`U256`].
///
/// Rejects empty strings and non-numeric values as validation errors.
fn parse_poll_id(s: &str) -> Result<U256, RelayError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(RelayError::Validation("poll id is empty".into()));
    }
    let radix_and_digits = if let Some(hex) = trimmed.strip_prefix("0x") {
        (16, hex)
    } else {
        (10, trimmed)
    };
    U256::from_str_radix(radix_and_digits.1, radix_and_digits.0)
        .map_err(|_| RelayError::Validation(format!("invalid poll id: {}", s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- constant_time_eq ---------------------------------------------

    #[test]
    fn constant_time_eq_accepts_matching_strings() {
        assert!(constant_time_eq("secret-key", "secret-key"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn constant_time_eq_rejects_different_content_same_length() {
        assert!(!constant_time_eq("secret-key", "secret-kex"));
    }

    #[test]
    fn constant_time_eq_rejects_different_length() {
        assert!(!constant_time_eq("short", "much-longer-string"));
        assert!(!constant_time_eq("", "nonempty"));
    }

    // ---- require_admin_auth --------------------------------------------

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    #[test]
    fn require_admin_auth_accepts_the_correct_key() {
        let headers = headers_with_bearer("s3cret");
        assert!(require_admin_auth(&headers, "s3cret").is_ok());
    }

    #[test]
    fn require_admin_auth_rejects_the_wrong_key() {
        let headers = headers_with_bearer("wrong");
        let err = require_admin_auth(&headers, "s3cret").unwrap_err();
        assert!(matches!(err, RelayError::Unauthorized));
    }

    #[test]
    fn require_admin_auth_rejects_a_missing_header() {
        let headers = HeaderMap::new();
        assert!(matches!(
            require_admin_auth(&headers, "s3cret"),
            Err(RelayError::Unauthorized)
        ));
    }

    #[test]
    fn require_admin_auth_rejects_a_non_bearer_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic czNjcmV0".parse().unwrap(),
        );
        assert!(matches!(
            require_admin_auth(&headers, "s3cret"),
            Err(RelayError::Unauthorized)
        ));
    }

    #[test]
    fn require_admin_auth_rejects_an_empty_bearer_token() {
        let headers = headers_with_bearer("");
        assert!(matches!(
            require_admin_auth(&headers, "s3cret"),
            Err(RelayError::Unauthorized)
        ));
    }

    #[test]
    fn require_admin_auth_rejects_empty_token_against_empty_expected() {
        // Even if ADMIN_API_KEY were somehow empty, an empty bearer token
        // must never be treated as a match.
        let headers = headers_with_bearer("");
        assert!(matches!(
            require_admin_auth(&headers, ""),
            Err(RelayError::Unauthorized)
        ));
    }

    // ---- validate_create_poll_request -----------------------------------

    fn valid_create_poll_request() -> CreatePollRequest {
        CreatePollRequest {
            merkle_root: B256::ZERO,
            num_options: U256::from(2u64),
            deadline: U256::from(1_893_456_000u64),
            metadata_uri: "ipfs://demo".into(),
        }
    }

    #[test]
    fn validate_create_poll_request_accepts_well_formed_input() {
        assert!(validate_create_poll_request(&valid_create_poll_request()).is_ok());
    }

    #[test]
    fn validate_create_poll_request_rejects_fewer_than_two_options() {
        let mut req = valid_create_poll_request();
        req.num_options = U256::from(1u64);
        let err = validate_create_poll_request(&req).unwrap_err();
        assert!(matches!(err, RelayError::Validation(_)));
    }

    #[test]
    fn validate_create_poll_request_rejects_zero_deadline() {
        let mut req = valid_create_poll_request();
        req.deadline = U256::ZERO;
        let err = validate_create_poll_request(&req).unwrap_err();
        assert!(matches!(err, RelayError::Validation(_)));
    }

    // ---- CreatePollRequest JSON shape -------------------------------------

    #[test]
    fn create_poll_request_deserializes_from_json() {
        let json = r#"{
            "merkle_root": "0x1111111122222222333333334444444455555555666666667777777788888888",
            "num_options": "3",
            "deadline": "1893456000",
            "metadata_uri": "ipfs://demo-poll"
        }"#;
        let req: CreatePollRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.num_options, U256::from(3u64));
        assert_eq!(req.deadline, U256::from(1_893_456_000u64));
        assert_eq!(req.metadata_uri, "ipfs://demo-poll");
    }

    #[test]
    fn create_poll_request_defaults_metadata_uri_when_omitted() {
        let json = r#"{
            "merkle_root": "0x1111111122222222333333334444444455555555666666667777777788888888",
            "num_options": "3",
            "deadline": "1893456000"
        }"#;
        let req: CreatePollRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.metadata_uri, "");
    }

    // ---- parse_poll_id ----------------------------------------------------

    #[test]
    fn parse_poll_id_accepts_decimal_and_hex() {
        assert_eq!(parse_poll_id("42").unwrap(), U256::from(42u64));
        assert_eq!(parse_poll_id("0x2a").unwrap(), U256::from(42u64));
    }

    #[test]
    fn parse_poll_id_rejects_empty_and_garbage() {
        assert!(parse_poll_id("").is_err());
        assert!(parse_poll_id("not-a-number").is_err());
    }
}
