//! Axum HTTP handlers for the Viche relayer.
//!
//! Endpoints:
//!   - `GET  /health`            — liveness check (always 200).
//!   - `POST /api/vote`          — accept a ZK proof + vote, broadcast on-chain.
//!   - `GET  /api/polls`         — list all polls.
//!   - `GET  /api/polls/:id`     — fetch a single poll's metadata.
//!   - `GET  /api/polls/:id/tally` — fetch a poll's per-option tallies.
//!
//! The vote handler is a thin shim: parse → validate → relay → respond.
//! The poll handlers delegate to [`crate::queries`] for the chain reads.

use alloy::network::Ethereum;
use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::transports::Transport;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use viche_core::wire::{PollData, PollListResponse, TallyResponse, VoteRequest, VoteResponse};

use crate::error::RelayError;
use crate::queries::{fetch_all_polls, fetch_poll, fetch_tally};
use crate::relay::submit_vote;

/// Application state shared across all handlers via Axum's `State` extractor.
///
/// Holds the alloy provider (HTTP transport + wallet fillers, already
/// connected) and the on-chain `VotingManager` address. Both are read-only
/// after construction; `Clone` is cheap (the provider is internally `Arc`'d).
#[derive(Clone)]
pub struct AppState<P> {
    pub provider: P,
    pub voting_manager_address: Address,
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
