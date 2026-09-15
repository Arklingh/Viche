//! Axum HTTP handlers for the Viche relayer.
//!
//! Endpoints:
//!   - `GET  /health`            — liveness: is the process up? Never touches
//!     the chain, so a monitoring system can tell "relayer crashed" apart
//!     from "relayer's RPC is down".
//!   - `GET  /ready`             — readiness: RPC reachable *and* the relayer
//!     wallet can still pay for votes.
//!   - `POST /api/vote`          — accept a ZK proof + vote, broadcast on-chain.
//!   - `GET  /api/polls`         — list all polls.
//!   - `GET  /api/polls/:id`     — fetch a single poll's metadata.
//!   - `GET  /api/polls/:id/tally` — fetch a poll's per-option tallies.
//!   - `POST /api/admin/polls`        — owner-only: create a poll.
//!   - `POST /api/admin/polls/:id/close` — owner-only: close a poll.
//!   - `POST /api/register`           — gated: submit an identity commitment.
//!   - `GET  /api/admin/registrations/pending`  — owner-only: current batch
//!     (add `?detailed=true` for provenance and Sybil-cluster analysis).
//!   - `POST /api/admin/registrations/approve`  — owner-only: approve entries.
//!   - `POST /api/admin/registrations/reject`   — owner-only: discard entries.
//!   - `POST /api/admin/registrations/snapshot` — owner-only: lock in the batch.
//!   - `POST /api/admin/registrations/publish`  — owner-only: store its root.
//!   - `GET  /api/polls/:id/registrations` — public: a poll's commitment list.
//!
//! The vote handler is a thin shim: parse → validate → relay → respond.
//! The poll handlers delegate to [`crate::queries`] for the chain reads.
//! The admin handlers require `Authorization: Bearer <ADMIN_API_KEY>` and
//! sign with a separate key from the vote-relay path — see
//! [`crate::config::Config::admin_private_key`].
//! The registration handlers delegate to [`crate::registration`] — see that
//! module for why voter registration needs any relayer-side state at all,
//! and for the Sybil-resistance model.
//!
//! # Middleware layering
//!
//! [`router`] wraps the routes in, from innermost outward:
//!
//! 1. **Per-route body limits** — a vote is under a kilobyte; nothing on this
//!    API should be allowed to arrive at Axum's 2 MB default.
//! 2. **Per-route, per-IP rate limits** — strictest on the two endpoints that
//!    cost money (`/api/vote`) or grow state (`/api/register`).
//! 3. **Client-IP resolution** — must be outside the rate limiters, since
//!    they read the IP it resolves.
//! 4. **Concurrency limit** — sheds load past the in-flight ceiling so a hung
//!    RPC backend can't pile up unbounded work.
//! 5. **Timeout** — a whole-request deadline, so the same hung backend
//!    produces a 504 instead of an immortal request.
//! 6. **Security headers**, then **CORS** outermost, so preflights and
//!    error responses both carry the right headers.
//!
//! # Privacy in logs
//!
//! Nothing on the vote path logs the chosen option, the nullifier, or the
//! client IP. An access log line pairing an IP with a vote option would
//! reconstruct exactly the voter↔choice link the ZK proof exists to break;
//! `poll_id` and the (already public) transaction hash are the most that is
//! ever emitted, and the request-level trace layer records method and path
//! only.

use std::sync::Arc;

use alloy::network::Ethereum;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::transports::Transport;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use viche_core::field::ensure_in_field;
use viche_core::wire::{
    CommitmentListResponse, PollData, PollListResponse, PublishRegistrationRequest,
    PublishRegistrationResponse, RegisterRequest, RegisterResponse, TallyResponse, VoteRequest,
    VoteResponse,
};

use crate::config::{GasConfig, HealthConfig, HttpConfig};
use crate::eligibility::{EligibilityPolicy, EligibilityRequest};
use crate::error::RelayError;
use crate::middleware::{
    concurrency_limit, cors_layer, invite_code, rate_limit, resolve_client_ip, security_header_layers,
    ClientIp, ConcurrencyGuard, ProxyConfig,
};
use crate::queries::{fetch_all_polls, fetch_poll, fetch_tally};
use crate::ratelimit::RateLimiter;
use crate::registration::{PendingSummary, RegistrationStore};
use crate::relay::{
    format_gwei, submit_cancel_poll, submit_close_poll, submit_create_poll, submit_void_poll,
    submit_vote, AdminTxResponse,
};

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
    /// Pre-poll voter registration store — see [`crate::registration`].
    pub registrations: Arc<RegistrationStore>,
    /// Eligibility gate for `POST /api/register` — see [`crate::eligibility`].
    pub eligibility: Arc<dyn EligibilityPolicy>,
    /// The relayer's gas-paying address, for the readiness balance check.
    pub relayer_address: Address,
    /// Spend guards applied before any broadcast.
    pub gas: GasConfig,
    /// Readiness thresholds.
    pub health: HealthConfig,
}

/// Build the Axum router from the given state and HTTP middleware config.
///
/// `P` must implement `Provider` over *some* transport `T` so the router is
/// agnostic to whether the underlying connection is reqwest, hyper, etc.
///
/// See the module docs for the layer ordering and why it is that order.
pub fn router<P, T>(state: AppState<P>, http: &HttpConfig) -> Router
where
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    T: Transport + Clone + Send + Sync + 'static,
{
    let vote_limiter = Arc::new(RateLimiter::new(
        http.rate_limit_vote,
        http.rate_limit_max_tracked_ips,
    ));
    let register_limiter = Arc::new(RateLimiter::new(
        http.rate_limit_register,
        http.rate_limit_max_tracked_ips,
    ));
    let read_limiter = Arc::new(RateLimiter::new(
        http.rate_limit_read,
        http.rate_limit_max_tracked_ips,
    ));
    let admin_limiter = Arc::new(RateLimiter::new(
        http.rate_limit_admin,
        http.rate_limit_max_tracked_ips,
    ));

    // The two endpoints that cost the relayer something: a vote spends ETH,
    // a registration grows persistent state. Tightest limits and tightest
    // body caps live here.
    let vote_routes = Router::new()
        .route("/api/vote", post(cast_vote::<P, T>))
        .layer(DefaultBodyLimit::max(http.max_vote_body_bytes))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&vote_limiter),
            rate_limit,
        ));

    let register_routes = Router::new()
        .route("/api/register", post(register::<P, T>))
        .layer(DefaultBodyLimit::max(http.max_register_body_bytes))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&register_limiter),
            rate_limit,
        ));

    // Admin routes are already bearer-gated, but rate-limiting them also
    // throttles brute-forcing the shared secret.
    let admin_routes = Router::new()
        .route("/api/admin/polls", post(create_poll::<P, T>))
        .route("/api/admin/polls/:id/close", post(close_poll::<P, T>))
        .route("/api/admin/polls/:id/cancel", post(cancel_poll::<P, T>))
        .route("/api/admin/polls/:id/void", post(void_poll::<P, T>))
        .route(
            "/api/admin/registrations/pending",
            get(pending_registrations::<P, T>),
        )
        .route(
            "/api/admin/registrations/approve",
            post(approve_registrations::<P, T>),
        )
        .route(
            "/api/admin/registrations/reject",
            post(reject_registrations::<P, T>),
        )
        .route(
            "/api/admin/registrations/snapshot",
            post(snapshot_registrations::<P, T>),
        )
        .route(
            "/api/admin/registrations/publish",
            post(publish_registration::<P, T>),
        )
        .layer(DefaultBodyLimit::max(http.max_admin_body_bytes))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&admin_limiter),
            rate_limit,
        ));

    let read_routes = Router::new()
        .route("/ready", get(readiness::<P, T>))
        .route("/api/polls", get(list_polls::<P, T>))
        .route("/api/polls/:id", get(get_poll::<P, T>))
        .route("/api/polls/:id/tally", get(get_tally::<P, T>))
        .route(
            "/api/polls/:id/registrations",
            get(poll_registrations::<P, T>),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&read_limiter),
            rate_limit,
        ));

    let proxy = ProxyConfig {
        trust_proxy_headers: http.trust_proxy_headers,
        trusted_proxy_hops: http.trusted_proxy_hops,
    };
    let guard = ConcurrencyGuard::new(http.max_concurrent_requests);

    let mut app = Router::new()
        // Liveness is deliberately outside every limiter: an orchestrator
        // must never be told the process is dead because it is busy.
        .route("/health", get(health))
        .merge(vote_routes)
        .merge(register_routes)
        .merge(admin_routes)
        .merge(read_routes)
        .with_state(state)
        .layer(DefaultBodyLimit::max(http.max_body_bytes))
        .layer(axum::middleware::from_fn_with_state(
            proxy,
            resolve_client_ip,
        ))
        .layer(axum::middleware::from_fn_with_state(
            guard,
            concurrency_limit,
        ))
        // 504 rather than tower-http's default 408: the deadline that
        // elapsed is the relayer's own wait on an upstream RPC, which is a
        // gateway timeout, not the client being slow to send its request.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            http.request_timeout,
        ));

    for layer in security_header_layers() {
        app = app.layer(layer);
    }

    app.layer(cors_layer(http)).layer(TraceLayer::new_for_http())
}

// =========================================================================
// Health / readiness
// =========================================================================

/// `GET /health`
///
/// **Liveness only.** Returns 200 as long as the process can serve a
/// request. Deliberately does no chain I/O: an orchestrator that restarts
/// the relayer because its RPC provider had a bad minute would turn a
/// degraded dependency into an outage. Use `/ready` to decide whether to
/// send traffic.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(LivenessResponse { status: "ok" }))
}

#[derive(Debug, serde::Serialize)]
struct LivenessResponse {
    status: &'static str,
}

/// How healthy the relayer's ability to actually relay is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthLevel {
    /// RPC reachable and the wallet is comfortably funded.
    Ok,
    /// Still serving, but the wallet is running low — page someone.
    Degraded,
    /// Cannot reliably relay: RPC unreachable, or the wallet is effectively
    /// empty. Reported with 503 so a load balancer drains this instance.
    Unhealthy,
}

impl HealthLevel {
    fn status_code(self) -> StatusCode {
        match self {
            Self::Ok | Self::Degraded => StatusCode::OK,
            Self::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// Classify a relayer-wallet balance against the configured thresholds.
///
/// Split out as a pure function so the thresholds can be tested without a
/// chain. `low` is always >= `min` (enforced in [`HealthConfig`]), so the
/// bands are `[0, min) = Unhealthy`, `[min, low) = Degraded`, `[low, ∞) = Ok`.
pub(crate) fn classify_balance(balance: U256, cfg: &HealthConfig) -> HealthLevel {
    if balance < cfg.min_balance_wei {
        HealthLevel::Unhealthy
    } else if balance < cfg.low_balance_wei {
        HealthLevel::Degraded
    } else {
        HealthLevel::Ok
    }
}

/// Body of `GET /ready`.
#[derive(Debug, serde::Serialize)]
struct ReadinessResponse {
    status: HealthLevel,
    /// Whether the RPC endpoint answered at all.
    rpc_reachable: bool,
    /// Latest block height, if the RPC answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    block_number: Option<u64>,
    /// The relayer's gas wallet.
    relayer_address: Address,
    /// Its balance in wei, as a decimal string.
    #[serde(skip_serializing_if = "Option::is_none")]
    relayer_balance_wei: Option<String>,
    /// The same balance rendered in gwei, for humans reading a dashboard.
    #[serde(skip_serializing_if = "Option::is_none")]
    relayer_balance_gwei: Option<String>,
    /// Which eligibility gate is installed on `/api/register`.
    eligibility_policy: &'static str,
    /// Human-readable explanation of a non-`ok` status.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// `GET /ready`
///
/// **Readiness.** Actually checks the two things that determine whether this
/// instance can do its job:
///
/// 1. the JSON-RPC endpoint answers (`eth_blockNumber`), and
/// 2. the relayer wallet still holds enough ETH to pay for votes.
///
/// Reports 503 when either fails, and `degraded` (still 200) when the
/// balance has fallen below the warning threshold but not the hard floor —
/// so monitoring can page while the relayer is still working, rather than
/// only once it has already stopped.
///
/// Unauthenticated, like `/health`, and deliberately reveals nothing beyond
/// the relayer's own public address and balance (both already visible
/// on-chain to anyone who looks).
async fn readiness<P, T>(State(state): State<AppState<P>>) -> impl IntoResponse
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    let block_number = match state.provider.get_block_number().await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "readiness: RPC endpoint unreachable");
            let body = ReadinessResponse {
                status: HealthLevel::Unhealthy,
                rpc_reachable: false,
                block_number: None,
                relayer_address: state.relayer_address,
                relayer_balance_wei: None,
                relayer_balance_gwei: None,
                eligibility_policy: state.eligibility.name(),
                detail: Some(format!("RPC endpoint unreachable: {e}")),
            };
            return (HealthLevel::Unhealthy.status_code(), Json(body));
        }
    };

    let balance = match state.provider.get_balance(state.relayer_address).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "readiness: could not read relayer balance");
            let body = ReadinessResponse {
                status: HealthLevel::Unhealthy,
                rpc_reachable: true,
                block_number: Some(block_number),
                relayer_address: state.relayer_address,
                relayer_balance_wei: None,
                relayer_balance_gwei: None,
                eligibility_policy: state.eligibility.name(),
                detail: Some(format!("could not read the relayer wallet balance: {e}")),
            };
            return (HealthLevel::Unhealthy.status_code(), Json(body));
        }
    };

    let status = classify_balance(balance, &state.health);
    let detail = match status {
        HealthLevel::Ok => None,
        HealthLevel::Degraded => Some(format!(
            "relayer wallet balance is low ({} gwei, warning threshold {} gwei); \
             top it up before it stops being able to pay for votes",
            balance_gwei(balance),
            balance_gwei(state.health.low_balance_wei),
        )),
        HealthLevel::Unhealthy => Some(format!(
            "relayer wallet balance ({} gwei) is below the minimum required to relay \
             votes ({} gwei); top it up",
            balance_gwei(balance),
            balance_gwei(state.health.min_balance_wei),
        )),
    };
    if status != HealthLevel::Ok {
        tracing::warn!(status = ?status, "readiness: relayer wallet balance below threshold");
    }

    let body = ReadinessResponse {
        status,
        rpc_reachable: true,
        block_number: Some(block_number),
        relayer_address: state.relayer_address,
        relayer_balance_wei: Some(balance.to_string()),
        relayer_balance_gwei: Some(balance_gwei(balance)),
        eligibility_policy: state.eligibility.name(),
        detail,
    };
    (status.status_code(), Json(body))
}

/// Render a `U256` wei balance as gwei, saturating rather than wrapping on
/// an implausibly large value.
fn balance_gwei(wei: U256) -> String {
    format_gwei(u128::try_from(wei).unwrap_or(u128::MAX))
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

    // Nothing here logs `vote_option`, `nullifier_hash`, or the client IP.
    // `vote_option` at info level was an IP-to-choice correlation waiting to
    // be joined against the reverse proxy's access log — the exact linkage
    // the ZK proof exists to prevent. `poll_id` alone is retained because
    // ops genuinely need to know which poll is seeing traffic, and it is
    // already public on-chain.
    tracing::debug!(poll_id = %req.poll_id, "validated vote request");

    // 2. Broadcast the castVote transaction on-chain (subject to the
    //    gas-price ceiling).
    let resp = submit_vote(
        state.provider,
        state.voting_manager_address,
        req.poll_id,
        &req.nullifier_hash,
        &req.proof,
        req.vote_option,
        state.gas.max_fee_per_gas_wei,
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
        state.gas.max_fee_per_gas_wei,
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

    let resp = submit_close_poll(
        state.admin_provider,
        state.voting_manager_address,
        poll_id,
        state.gas.max_fee_per_gas_wei,
    )
    .await?;
    Ok(Json(resp))
}

/// Body for the two poll-retirement endpoints.
///
/// `reason` is not decoration: both operations end a poll early, and both are
/// recorded on-chain with this string so the decision is publicly auditable
/// after the fact. It is required rather than optional for exactly that
/// reason.
#[derive(Debug, serde::Deserialize)]
struct RetirePollRequest {
    reason: String,
}

/// Longest `reason` accepted. Bounded because it is attacker-influenced only
/// by the admin, but still ends up as calldata the owner pays gas for.
const MAX_REASON_LEN: usize = 200;

fn validate_reason(reason: &str) -> Result<String, RelayError> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return Err(RelayError::Validation(
            "a reason is required: retiring a poll is recorded on-chain for audit".into(),
        ));
    }
    if trimmed.len() > MAX_REASON_LEN {
        return Err(RelayError::Validation(format!(
            "reason must be at most {MAX_REASON_LEN} characters"
        )));
    }
    Ok(trimmed.to_string())
}

/// `POST /api/admin/polls/:id/cancel`
///
/// Owner-only. Retires a poll **nobody has voted in** — the escape hatch for a
/// misconfigured poll. Fails with a clear message once any ballot has landed,
/// since cancelling then would revoke votes already cast.
async fn cancel_poll<P, T>(
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<RetirePollRequest>,
) -> Result<Json<AdminTxResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    require_admin_auth(&headers, &state.admin_api_key)?;
    let poll_id = parse_poll_id(&id)?;
    let reason = validate_reason(&req.reason)?;

    let resp = submit_cancel_poll(
        state.admin_provider,
        state.voting_manager_address,
        poll_id,
        reason,
        state.gas.max_fee_per_gas_wei,
    )
    .await?;
    Ok(Json(resp))
}

/// `POST /api/admin/polls/:id/void`
///
/// Owner-only. Abandons a running poll and **discards its tally** — the
/// emergency hatch. Deliberately not a way to win: the result becomes
/// unreadable rather than frozen, so voiding can only ever produce "no
/// result", never a favourable partial count.
async fn void_poll<P, T>(
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<RetirePollRequest>,
) -> Result<Json<AdminTxResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    require_admin_auth(&headers, &state.admin_api_key)?;
    let poll_id = parse_poll_id(&id)?;
    let reason = validate_reason(&req.reason)?;

    let resp = submit_void_poll(
        state.admin_provider,
        state.voting_manager_address,
        poll_id,
        reason,
        state.gas.max_fee_per_gas_wei,
    )
    .await?;
    Ok(Json(resp))
}

/// `POST /api/register`
///
/// Submit an identity commitment ahead of the next poll.
///
/// **Not open.** An earlier version of this endpoint accepted anything from
/// anyone on the theory that a commitment is a one-way hash and the admin
/// decides what becomes a whitelist. Confidentiality was never the problem:
/// an attacker who submits 10,000 distinct commitments — each a hash of a
/// secret only they hold — is indistinguishable from 10,000 voters, and owns
/// the electorate if that batch is ever published. See [`crate::registration`]
/// for the full corrected model.
///
/// Every submission must now pass:
///
/// 1. the endpoint's per-IP rate limit (applied as middleware),
/// 2. the configured eligibility gate — by default an invite code supplied
///    in the `X-Invite-Code` header (see [`crate::eligibility`]), and
/// 3. the per-source and per-batch caps in the store,
///
/// and, unless `REGISTRATION_REQUIRE_APPROVAL=false`, lands as *pending
/// approval* rather than as an accepted member of the next electorate.
async fn register<P, T>(
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    client_ip: Option<axum::Extension<ClientIp>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    ensure_in_field(&req.commitment).map_err(|e| RelayError::Validation(e.to_string()))?;

    // The raw IP is used only to derive an opaque, salted id and is never
    // stored, logged, or returned. See `RegistrationStore::source_id`.
    let source_id = match client_ip {
        Some(axum::Extension(ClientIp(ip))) => state.registrations.source_id(ip),
        None => "unknown".to_string(),
    };

    let code = invite_code(&headers);
    let grant = state
        .eligibility
        .check(&EligibilityRequest {
            commitment: &req.commitment,
            invite_code: code.as_deref(),
            source_id: &source_id,
        })
        .map_err(|denied| {
            // Log that a registration was refused and by which policy, but
            // never the commitment, the code, or the source.
            tracing::info!(policy = state.eligibility.name(), "registration refused");
            RelayError::NotEligible(denied.0)
        })?;

    let total_pending = state
        .registrations
        .register(req.commitment, source_id, grant.note)
        .await?;
    Ok(Json(RegisterResponse { total_pending }))
}

/// Query string for `GET /api/admin/registrations/pending`.
#[derive(Debug, Default, serde::Deserialize)]
struct PendingQuery {
    /// When true, return provenance and Sybil-cluster analysis instead of a
    /// bare commitment list.
    #[serde(default)]
    detailed: bool,
}

/// Either shape of the pending-registrations response.
///
/// Untagged so `?detailed=true` changes the body without changing the
/// status code or adding an envelope the existing admin UI would have to
/// learn about.
#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
enum PendingResponse {
    Plain(CommitmentListResponse),
    Detailed(Box<PendingSummary>),
}

/// `GET /api/admin/registrations/pending[?detailed=true]`
///
/// Owner-only. Returns the commitment batch collected since the last
/// `snapshot` call.
///
/// Without `detailed`, this is the flat commitment list it has always been.
/// With it, each entry carries its submission time, the eligibility note
/// that admitted it, an opaque source id, and its approval state — plus a
/// `source_clusters` summary highlighting any source that submitted more
/// than once. That is the whole point of the review step: approving a batch
/// where one source accounts for 400 of 420 registrations should look
/// obviously wrong, and it cannot look wrong if the admin is only ever shown
/// an anonymous list of numbers.
async fn pending_registrations<P, T>(
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Query(query): Query<PendingQuery>,
) -> Result<Json<PendingResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    require_admin_auth(&headers, &state.admin_api_key)?;
    if query.detailed {
        let summary = state.registrations.pending_detailed().await;
        Ok(Json(PendingResponse::Detailed(Box::new(summary))))
    } else {
        let commitments = state.registrations.pending().await;
        Ok(Json(PendingResponse::Plain(CommitmentListResponse {
            commitments,
        })))
    }
}

/// Request body for the approve/reject admin endpoints.
#[derive(Debug, Default, serde::Deserialize)]
struct ReviewRequest {
    /// Commitments to act on. Ignored when `all` is true.
    #[serde(default)]
    commitments: Vec<U256>,
    /// Act on every pending entry. Only honoured by `approve`.
    #[serde(default)]
    all: bool,
}

/// Response body for the approve/reject admin endpoints.
#[derive(Debug, serde::Serialize)]
struct ReviewResponse {
    /// How many entries changed state.
    affected: usize,
    /// Commitments that weren't in the pending batch (approve only), so a
    /// mistyped list is visible rather than silently partially applied.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unknown: Vec<U256>,
    /// How many entries remain pending afterwards.
    total_pending: usize,
}

/// `POST /api/admin/registrations/approve`
///
/// Owner-only. Marks pending commitments as approved so the next `snapshot`
/// will include them. Body is either `{"commitments": ["1", "2"]}` or
/// `{"all": true}`.
///
/// `all` is still an explicit act on an explicit batch — "I have reviewed
/// this list" — not a way to turn the review step off. To do that, set
/// `REGISTRATION_REQUIRE_APPROVAL=false`, which is at least visible in the
/// deployment's configuration.
async fn approve_registrations<P, T>(
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Json(req): Json<ReviewRequest>,
) -> Result<Json<ReviewResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    require_admin_auth(&headers, &state.admin_api_key)?;

    let (affected, unknown) = if req.all {
        (state.registrations.approve_all().await?, Vec::new())
    } else {
        if req.commitments.is_empty() {
            return Err(RelayError::Validation(
                "supply either a non-empty `commitments` list or `\"all\": true`".into(),
            ));
        }
        state.registrations.approve(&req.commitments).await?
    };

    tracing::info!(approved = affected, "admin approved registrations");
    Ok(Json(ReviewResponse {
        affected,
        unknown,
        total_pending: state.registrations.pending().await.len(),
    }))
}

/// `POST /api/admin/registrations/reject`
///
/// Owner-only. Discards pending commitments outright. The counterpart to
/// approval: an admin who spots a Sybil cluster in review needs to be able
/// to remove it, not merely to decline to approve it — an unapproved entry
/// sits in the batch forever, consuming the batch cap.
///
/// There is deliberately no `all` shortcut here. Wiping an entire batch of
/// registrations should require naming what is being wiped.
async fn reject_registrations<P, T>(
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Json(req): Json<ReviewRequest>,
) -> Result<Json<ReviewResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    require_admin_auth(&headers, &state.admin_api_key)?;
    if req.commitments.is_empty() {
        return Err(RelayError::Validation(
            "supply a non-empty `commitments` list to reject".into(),
        ));
    }

    let affected = state.registrations.reject(&req.commitments).await?;
    tracing::info!(rejected = affected, "admin rejected registrations");
    Ok(Json(ReviewResponse {
        affected,
        unknown: Vec::new(),
        total_pending: state.registrations.pending().await.len(),
    }))
}

/// `POST /api/admin/registrations/snapshot`
///
/// Owner-only. Atomically locks in the *approved* part of the current
/// pending batch (any further `/api/register` calls, and anything left
/// unapproved, stay pending for the *next* poll) and returns it so the
/// admin's browser can build a Merkle tree and compute the root. Follow up
/// with `POST /api/admin/registrations/publish` once that root is known.
///
/// Errors if the batch is non-empty but nothing in it has been approved,
/// rather than returning an empty list — publishing an empty root would
/// create a poll in which nobody can vote.
async fn snapshot_registrations<P, T>(
    State(state): State<AppState<P>>,
    headers: HeaderMap,
) -> Result<Json<CommitmentListResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    require_admin_auth(&headers, &state.admin_api_key)?;
    let commitments = state.registrations.snapshot().await?;
    Ok(Json(CommitmentListResponse { commitments }))
}

/// `POST /api/admin/registrations/publish`
///
/// Owner-only. Stores the most recent snapshot under `merkle_root` so
/// `GET /api/polls/:id/registrations` can later serve it to voters. Errors
/// if no snapshot is pending (i.e. `snapshot` was never called, or already
/// published under a different root — republishing under the same list's
/// true root is harmless and idempotent).
async fn publish_registration<P, T>(
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Json(req): Json<PublishRegistrationRequest>,
) -> Result<Json<PublishRegistrationResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    require_admin_auth(&headers, &state.admin_api_key)?;
    let commitment_count = state.registrations.publish(req.merkle_root).await?;
    Ok(Json(PublishRegistrationResponse { commitment_count }))
}

/// `GET /api/polls/:id/registrations`
///
/// Public. Looks up the poll's on-chain `merkle_root`, then returns the
/// commitment list published under that root (if any) — the leaf set a
/// voter's browser needs to rebuild the tree and extract its own membership
/// proof. Returns a validation error if the poll wasn't created via the
/// registration flow (e.g. a hand-computed root with no published list).
async fn poll_registrations<P, T>(
    State(state): State<AppState<P>>,
    Path(id): Path<String>,
) -> Result<Json<CommitmentListResponse>, RelayError>
where
    P: Provider<T, Ethereum> + Clone + Send + Sync,
    T: Transport + Clone,
{
    let poll_id = parse_poll_id(&id)?;
    let poll = fetch_poll(state.provider, state.voting_manager_address, poll_id).await?;
    let commitments = state
        .registrations
        .for_root(&poll.merkle_root)
        .await
        .ok_or_else(|| {
            RelayError::Validation(format!(
                "no registration data found for poll {} (it may have been created \
                 without the registration flow)",
                poll_id
            ))
        })?;
    Ok(Json(CommitmentListResponse { commitments }))
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

    // ---- validate_reason --------------------------------------------------

    #[test]
    fn validate_reason_accepts_and_trims() {
        assert_eq!(validate_reason("  wrong root  ").unwrap(), "wrong root");
    }

    /// Retiring a poll is recorded on-chain for audit, so an empty reason
    /// defeats the point of recording it.
    #[test]
    fn validate_reason_rejects_blank() {
        assert!(matches!(validate_reason("   "), Err(RelayError::Validation(_))));
        assert!(matches!(validate_reason(""), Err(RelayError::Validation(_))));
    }

    #[test]
    fn validate_reason_rejects_overlong() {
        let long = "x".repeat(MAX_REASON_LEN + 1);
        assert!(matches!(validate_reason(&long), Err(RelayError::Validation(_))));
        let ok = "x".repeat(MAX_REASON_LEN);
        assert!(validate_reason(&ok).is_ok());
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

    // ---- classify_balance ------------------------------------------------

    fn health_cfg(min: u64, low: u64) -> HealthConfig {
        HealthConfig {
            min_balance_wei: U256::from(min),
            low_balance_wei: U256::from(low),
        }
    }

    #[test]
    fn classify_balance_bands_are_min_low_and_above() {
        let cfg = health_cfg(100, 500);
        assert_eq!(classify_balance(U256::from(0u64), &cfg), HealthLevel::Unhealthy);
        assert_eq!(classify_balance(U256::from(99u64), &cfg), HealthLevel::Unhealthy);
        // The hard floor is inclusive: exactly `min` is degraded, not dead.
        assert_eq!(classify_balance(U256::from(100u64), &cfg), HealthLevel::Degraded);
        assert_eq!(classify_balance(U256::from(499u64), &cfg), HealthLevel::Degraded);
        assert_eq!(classify_balance(U256::from(500u64), &cfg), HealthLevel::Ok);
        assert_eq!(classify_balance(U256::MAX, &cfg), HealthLevel::Ok);
    }

    #[test]
    fn classify_balance_with_equal_thresholds_has_no_degraded_band() {
        let cfg = health_cfg(100, 100);
        assert_eq!(classify_balance(U256::from(99u64), &cfg), HealthLevel::Unhealthy);
        assert_eq!(classify_balance(U256::from(100u64), &cfg), HealthLevel::Ok);
    }

    #[test]
    fn only_unhealthy_readiness_sheds_traffic() {
        assert_eq!(HealthLevel::Ok.status_code(), StatusCode::OK);
        // Degraded still serves - the point is to page, not to go dark.
        assert_eq!(HealthLevel::Degraded.status_code(), StatusCode::OK);
        assert_eq!(
            HealthLevel::Unhealthy.status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn balance_gwei_saturates_instead_of_wrapping() {
        assert_eq!(balance_gwei(U256::from(1_000_000_000u64)), "1.00");
        // A balance larger than u128 can't be rendered exactly; it must not
        // wrap around to a small number and read as "wallet is empty".
        assert_eq!(balance_gwei(U256::MAX), format_gwei(u128::MAX));
    }

    // =====================================================================
    // Router / middleware integration
    //
    // These drive the fully-assembled `router()` with `oneshot`, so the
    // middleware stack is exercised exactly as it is layered in production.
    // The provider points at a closed port: every route asserted here
    // rejects the request before any chain I/O, which is itself part of what
    // is being tested (a body-cap or rate-limit rejection must not first
    // cost an RPC round trip).
    // =====================================================================

    mod router_tests {
        use super::*;
        use crate::config::{EligibilityPolicyKind, RateLimitRule, RegistrationConfig};
        use crate::eligibility::OpenPolicy;
        use alloy::providers::ProviderBuilder;
        use alloy::transports::http::{Client as HttpClient, Http};
        use axum::body::Body;
        use axum::http::{header, Request};
        use std::collections::HashMap;
        use std::net::SocketAddr;
        use tower::ServiceExt;

        type TestProvider = alloy::providers::RootProvider<Http<HttpClient>>;

        fn test_http_config() -> HttpConfig {
            HttpConfig {
                cors_allowed_origins: Vec::new(),
                trust_proxy_headers: false,
                trusted_proxy_hops: 1,
                rate_limit_vote: RateLimitRule {
                    per_minute: 5,
                    burst: 2,
                },
                rate_limit_register: RateLimitRule {
                    per_minute: 3,
                    burst: 2,
                },
                rate_limit_read: RateLimitRule {
                    per_minute: 120,
                    burst: 60,
                },
                rate_limit_admin: RateLimitRule {
                    per_minute: 60,
                    burst: 30,
                },
                rate_limit_max_tracked_ips: 1000,
                max_vote_body_bytes: 4096,
                max_register_body_bytes: 1024,
                max_admin_body_bytes: 65536,
                max_body_bytes: 16384,
                request_timeout: std::time::Duration::from_secs(20),
                max_concurrent_requests: 64,
            }
        }

        fn registration_cfg() -> RegistrationConfig {
            RegistrationConfig {
                policy: EligibilityPolicyKind::Open,
                invite_codes: HashMap::new(),
                allowlist_file: None,
                require_approval: true,
                max_per_source: 5,
                max_pending: 10_000,
            }
        }

        async fn test_state() -> AppState<TestProvider> {
            // Port 1 is never bound; any handler that actually reaches the
            // chain will fail, which is what we want - these tests assert on
            // paths that short-circuit first.
            let url: url::Url = "http://127.0.0.1:1".parse().unwrap();
            let provider = ProviderBuilder::new().on_http(url);

            let path = std::env::temp_dir().join(format!(
                "viche-router-test-{}-{:?}.json",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let registrations = Arc::new(
                RegistrationStore::load(path, &registration_cfg())
                    .await
                    .unwrap(),
            );

            AppState {
                provider: provider.clone(),
                admin_provider: provider,
                voting_manager_address: Address::ZERO,
                admin_api_key: "test-admin-key".into(),
                registrations,
                eligibility: Arc::new(OpenPolicy),
                relayer_address: Address::ZERO,
                gas: GasConfig {
                    max_fee_per_gas_wei: 150_000_000_000,
                },
                health: health_cfg(100, 500),
            }
        }

        async fn test_app(http: &HttpConfig) -> Router {
            router::<TestProvider, Http<HttpClient>>(test_state().await, http)
        }

        /// A request carrying a synthetic peer address, so rate-limit tests
        /// can act as distinct clients.
        fn request_from(method: &str, uri: &str, ip: &str, body: Body) -> Request<Body> {
            let mut req = Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .unwrap();
            let addr: SocketAddr = format!("{ip}:54321").parse().unwrap();
            req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
            req
        }

        fn json_request(method: &str, uri: &str, ip: &str, body: &str) -> Request<Body> {
            request_from(method, uri, ip, Body::from(body.to_string()))
        }

        // ---- liveness ----------------------------------------------------

        #[tokio::test]
        async fn health_is_200_without_touching_the_chain() {
            let app = test_app(&test_http_config()).await;
            let resp = app
                .oneshot(request_from("GET", "/health", "10.0.0.1", Body::empty()))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn health_is_not_rate_limited() {
            // Liveness must never report failure because the service is
            // busy - an orchestrator would restart a perfectly healthy
            // process. 50 hits against a burst of 2 elsewhere.
            let app = test_app(&test_http_config()).await;
            for _ in 0..50 {
                let resp = app
                    .clone()
                    .oneshot(request_from("GET", "/health", "10.0.0.9", Body::empty()))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }
        }

        #[tokio::test]
        async fn readiness_reports_unhealthy_when_the_rpc_is_unreachable() {
            let app = test_app(&test_http_config()).await;
            let resp = app
                .oneshot(request_from("GET", "/ready", "10.0.0.1", Body::empty()))
                .await
                .unwrap();
            // Nothing is listening on port 1, so this is the real
            // "RPC down" path, not a mock of it.
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

            let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["status"], "unhealthy");
            assert_eq!(json["rpc_reachable"], false);
            assert!(json["detail"].as_str().unwrap().contains("RPC"));
        }

        // ---- security headers --------------------------------------------

        #[tokio::test]
        async fn every_response_carries_the_security_headers() {
            let app = test_app(&test_http_config()).await;
            let resp = app
                .oneshot(request_from("GET", "/health", "10.0.0.1", Body::empty()))
                .await
                .unwrap();
            let h = resp.headers();
            assert_eq!(h["x-content-type-options"], "nosniff");
            assert_eq!(h["x-frame-options"], "DENY");
            assert_eq!(h["referrer-policy"], "no-referrer");
            assert_eq!(h["cache-control"], "no-store");
            assert!(h["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'"));
        }

        #[tokio::test]
        async fn error_responses_also_carry_the_security_headers() {
            // Headers applied only on the happy path are worse than useless.
            let app = test_app(&test_http_config()).await;
            let resp = app
                .oneshot(json_request(
                    "GET",
                    "/api/admin/registrations/pending",
                    "10.0.0.1",
                    "",
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
        }

        // ---- CORS --------------------------------------------------------

        #[tokio::test]
        async fn no_allow_origin_header_is_emitted_by_default() {
            // Default must be same-origin-only, never `*`: these endpoints
            // spend the relayer's ETH.
            let app = test_app(&test_http_config()).await;
            let mut req = request_from("GET", "/health", "10.0.0.1", Body::empty());
            req.headers_mut()
                .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
            let resp = app.oneshot(req).await.unwrap();
            assert!(!resp
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        }

        #[tokio::test]
        async fn a_listed_origin_is_echoed_and_an_unlisted_one_is_not() {
            let mut cfg = test_http_config();
            cfg.cors_allowed_origins = vec!["https://vote.example.org".into()];
            let app = test_app(&cfg).await;

            let mut allowed = request_from("GET", "/health", "10.0.0.1", Body::empty());
            allowed
                .headers_mut()
                .insert(header::ORIGIN, "https://vote.example.org".parse().unwrap());
            let resp = app.clone().oneshot(allowed).await.unwrap();
            assert_eq!(
                resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
                "https://vote.example.org"
            );

            let mut denied = request_from("GET", "/health", "10.0.0.1", Body::empty());
            denied
                .headers_mut()
                .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
            let resp = app.oneshot(denied).await.unwrap();
            assert!(!resp
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        }

        // ---- body limits --------------------------------------------------

        #[tokio::test]
        async fn an_oversized_vote_body_is_rejected_before_any_chain_io() {
            let app = test_app(&test_http_config()).await;
            // 64 KiB - far over the 4 KiB vote cap, far under axum's 2 MB
            // default, so this only passes if our cap is actually installed.
            let huge = format!(r#"{{"poll_id":"1","padding":"{}"}}"#, "a".repeat(64 * 1024));
            let resp = app
                .oneshot(json_request("POST", "/api/vote", "10.0.0.1", &huge))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }

        #[tokio::test]
        async fn an_oversized_registration_body_is_rejected() {
            let app = test_app(&test_http_config()).await;
            let huge = format!(r#"{{"commitment":"1","padding":"{}"}}"#, "a".repeat(8192));
            let resp = app
                .oneshot(json_request("POST", "/api/register", "10.0.0.1", &huge))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }

        #[tokio::test]
        async fn a_normal_sized_vote_body_passes_the_cap_and_reaches_validation() {
            // The cap must not be so tight it rejects real votes: a
            // well-formed-shaped (if semantically invalid) vote should get
            // past the body limit and fail validation instead.
            let app = test_app(&test_http_config()).await;
            let proof = format!("0x{}", "00".repeat(256));
            let body = format!(
                r#"{{"poll_id":"1","vote_option":"0","nullifier_hash":"0x0","proof":"{proof}"}}"#
            );
            assert!(body.len() < 4096);
            let resp = app
                .oneshot(json_request("POST", "/api/vote", "10.0.0.1", &body))
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }

        // ---- rate limiting ------------------------------------------------

        #[tokio::test]
        async fn the_vote_endpoint_rate_limits_per_ip() {
            let app = test_app(&test_http_config()).await; // vote burst = 2
            let body = r#"{"poll_id":"0","vote_option":"0","nullifier_hash":"0x0","proof":"0x00"}"#;

            // Burst of 2: these are rejected on validation, not rate.
            for _ in 0..2 {
                let resp = app
                    .clone()
                    .oneshot(json_request("POST", "/api/vote", "10.0.0.2", body))
                    .await
                    .unwrap();
                assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            }

            let resp = app
                .clone()
                .oneshot(json_request("POST", "/api/vote", "10.0.0.2", body))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(resp.headers().contains_key(header::RETRY_AFTER));
        }

        #[tokio::test]
        async fn the_register_endpoint_rate_limits_per_ip() {
            // The other endpoint worth defending: each accepted call grows
            // persistent state and consumes a slot in the next electorate.
            let app = test_app(&test_http_config()).await; // register burst = 2
            for c in ["1", "2"] {
                let resp = app
                    .clone()
                    .oneshot(json_request(
                        "POST",
                        "/api/register",
                        "10.0.0.40",
                        &format!(r#"{{"commitment":"{c}"}}"#),
                    ))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }

            let resp = app
                .oneshot(json_request(
                    "POST",
                    "/api/register",
                    "10.0.0.40",
                    r#"{"commitment":"3"}"#,
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(resp.headers().contains_key(header::RETRY_AFTER));
        }

        #[tokio::test]
        async fn one_ips_rate_limit_does_not_affect_another() {
            let app = test_app(&test_http_config()).await;
            let body = r#"{"poll_id":"0","vote_option":"0","nullifier_hash":"0x0","proof":"0x00"}"#;

            for _ in 0..3 {
                let _ = app
                    .clone()
                    .oneshot(json_request("POST", "/api/vote", "10.0.0.3", body))
                    .await
                    .unwrap();
            }
            // 10.0.0.3 is now limited; a different client must not be.
            let resp = app
                .oneshot(json_request("POST", "/api/vote", "10.0.0.4", body))
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        #[tokio::test]
        async fn the_vote_and_register_limiters_are_independent() {
            // Exhausting the vote budget must not lock a voter out of
            // registering, and vice versa - they are separate buckets.
            let app = test_app(&test_http_config()).await;
            let vote = r#"{"poll_id":"0","vote_option":"0","nullifier_hash":"0x0","proof":"0x00"}"#;
            for _ in 0..3 {
                let _ = app
                    .clone()
                    .oneshot(json_request("POST", "/api/vote", "10.0.0.5", vote))
                    .await
                    .unwrap();
            }
            let resp = app
                .oneshot(json_request(
                    "POST",
                    "/api/register",
                    "10.0.0.5",
                    r#"{"commitment":"1"}"#,
                ))
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        #[tokio::test]
        async fn forged_forwarded_headers_cannot_evade_the_limiter_by_default() {
            // TRUST_PROXY_HEADERS defaults to false, so a fresh fake
            // X-Forwarded-For per request must not buy a fresh bucket.
            let app = test_app(&test_http_config()).await;
            let body = r#"{"poll_id":"0","vote_option":"0","nullifier_hash":"0x0","proof":"0x00"}"#;

            let mut statuses = Vec::new();
            for i in 0..4 {
                let mut req = json_request("POST", "/api/vote", "10.0.0.6", body);
                req.headers_mut().insert(
                    "x-forwarded-for",
                    format!("1.2.3.{i}").parse().unwrap(),
                );
                statuses.push(app.clone().oneshot(req).await.unwrap().status());
            }
            assert_eq!(statuses[3], StatusCode::TOO_MANY_REQUESTS);
        }

        #[tokio::test]
        async fn forwarded_headers_do_separate_buckets_when_proxy_trust_is_on() {
            let mut cfg = test_http_config();
            cfg.trust_proxy_headers = true;
            cfg.trusted_proxy_hops = 1;
            let app = test_app(&cfg).await;
            let body = r#"{"poll_id":"0","vote_option":"0","nullifier_hash":"0x0","proof":"0x00"}"#;

            // Same socket peer, four different real clients behind the proxy.
            for i in 0..4 {
                let mut req = json_request("POST", "/api/vote", "10.0.0.7", body);
                req.headers_mut().insert(
                    "x-forwarded-for",
                    format!("198.51.100.{i}").parse().unwrap(),
                );
                let resp = app.clone().oneshot(req).await.unwrap();
                assert_ne!(
                    resp.status(),
                    StatusCode::TOO_MANY_REQUESTS,
                    "client {i} should have its own bucket"
                );
            }
        }

        // ---- admin auth ---------------------------------------------------

        #[tokio::test]
        async fn admin_routes_reject_a_missing_key() {
            let app = test_app(&test_http_config()).await;
            for (method, uri) in [
                ("GET", "/api/admin/registrations/pending"),
                ("POST", "/api/admin/registrations/approve"),
                ("POST", "/api/admin/registrations/reject"),
                ("POST", "/api/admin/registrations/snapshot"),
            ] {
                let resp = app
                    .clone()
                    .oneshot(json_request(method, uri, "10.0.0.8", "{}"))
                    .await
                    .unwrap();
                assert_eq!(
                    resp.status(),
                    StatusCode::UNAUTHORIZED,
                    "{method} {uri} must require the admin key"
                );
            }
        }

        // ---- registration review flow, end to end through the router -----

        async fn admin_post(app: &Router, uri: &str, body: &str) -> (StatusCode, serde_json::Value) {
            let mut req = json_request("POST", uri, "10.0.0.20", body);
            req.headers_mut().insert(
                header::AUTHORIZATION,
                "Bearer test-admin-key".parse().unwrap(),
            );
            let resp = app.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            (status, json)
        }

        async fn admin_get(app: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
            let mut req = request_from("GET", uri, "10.0.0.20", Body::empty());
            req.headers_mut().insert(
                header::AUTHORIZATION,
                "Bearer test-admin-key".parse().unwrap(),
            );
            let resp = app.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            (status, json)
        }

        #[tokio::test]
        async fn registrations_require_approval_before_they_can_be_snapshotted() {
            let app = test_app(&test_http_config()).await;

            let resp = app
                .clone()
                .oneshot(json_request(
                    "POST",
                    "/api/register",
                    "10.0.0.21",
                    r#"{"commitment":"12345"}"#,
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            // Snapshot must refuse rather than silently produce an empty
            // root - a poll built on an empty tree has no voters.
            let (status, body) = admin_post(&app, "/api/admin/registrations/snapshot", "").await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(body["message"].as_str().unwrap().contains("approved"));

            // Approve, then it works.
            let (status, body) =
                admin_post(&app, "/api/admin/registrations/approve", r#"{"all":true}"#).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["affected"], 1);

            let (status, body) = admin_post(&app, "/api/admin/registrations/snapshot", "").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["commitments"].as_array().unwrap().len(), 1);
        }

        #[tokio::test]
        async fn the_detailed_pending_view_surfaces_provenance_and_clusters() {
            // Raise the register limiter out of the way: this test is about
            // the review payload, and the default burst of 2 would otherwise
            // 429 the third registration (which is itself asserted in
            // `the_register_endpoint_rate_limits_per_ip`).
            let mut http = test_http_config();
            http.rate_limit_register = RateLimitRule {
                per_minute: 600,
                burst: 100,
            };
            let app = test_app(&http).await;
            for c in ["1", "2", "3"] {
                let resp = app
                    .clone()
                    .oneshot(json_request(
                        "POST",
                        "/api/register",
                        "10.0.0.22",
                        &format!(r#"{{"commitment":"{c}"}}"#),
                    ))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }

            // Plain view is the flat list the existing admin UI expects.
            let (status, plain) =
                admin_get(&app, "/api/admin/registrations/pending").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(plain["commitments"].as_array().unwrap().len(), 3);

            // Detailed view carries what the admin needs to judge the batch.
            let (status, detailed) =
                admin_get(&app, "/api/admin/registrations/pending?detailed=true").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(detailed["unapproved"], 3);
            assert_eq!(detailed["approval_required"], true);
            let clusters = detailed["source_clusters"].as_array().unwrap();
            assert_eq!(clusters.len(), 1, "all three came from one source");
            assert_eq!(clusters[0]["count"], 3);
            let entry = &detailed["entries"][0];
            assert_eq!(entry["eligibility"], "open");
            assert!(entry["submitted_at"].as_u64().unwrap() > 0);
            // The raw client IP must never appear in an admin payload.
            assert!(!detailed.to_string().contains("10.0.0.22"));
        }

        #[tokio::test]
        async fn rejecting_removes_entries_and_requires_an_explicit_list() {
            let app = test_app(&test_http_config()).await;
            for c in ["7", "8"] {
                let _ = app
                    .clone()
                    .oneshot(json_request(
                        "POST",
                        "/api/register",
                        "10.0.0.23",
                        &format!(r#"{{"commitment":"{c}"}}"#),
                    ))
                    .await
                    .unwrap();
            }

            // There is deliberately no `all` shortcut for reject.
            let (status, _) =
                admin_post(&app, "/api/admin/registrations/reject", r#"{"all":true}"#).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);

            let (status, body) = admin_post(
                &app,
                "/api/admin/registrations/reject",
                r#"{"commitments":["7"]}"#,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["affected"], 1);
            assert_eq!(body["total_pending"], 1);
        }

        #[tokio::test]
        async fn an_ineligible_registration_is_403_and_is_not_stored() {
            // Swap in the invite-code gate and submit without a code.
            use crate::eligibility::InviteCodePolicy;
            let http = test_http_config();
            let mut state = test_state().await;
            let mut codes = HashMap::new();
            codes.insert("good-code".to_string(), None);
            state.eligibility = Arc::new(InviteCodePolicy::new(codes));
            let store = Arc::clone(&state.registrations);
            let app = router::<TestProvider, Http<HttpClient>>(state, &http);

            let resp = app
                .clone()
                .oneshot(json_request(
                    "POST",
                    "/api/register",
                    "10.0.0.24",
                    r#"{"commitment":"99"}"#,
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            assert!(store.pending().await.is_empty());

            // With the code, it goes through.
            let mut req = json_request(
                "POST",
                "/api/register",
                "10.0.0.25",
                r#"{"commitment":"99"}"#,
            );
            req.headers_mut()
                .insert("x-invite-code", "good-code".parse().unwrap());
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(store.pending().await.len(), 1);
        }

        #[tokio::test]
        async fn the_per_source_cap_is_enforced_through_the_router() {
            let http = test_http_config();
            let mut state = test_state().await;
            // Rebuild the store with a cap of 2 so the cap, not the rate
            // limiter, is what bites. Register burst is 2/minute here, so
            // raise the limiter out of the way for this test.
            let path = std::env::temp_dir().join(format!(
                "viche-cap-test-{}-{:?}.json",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            state.registrations = Arc::new(
                RegistrationStore::load(
                    path,
                    &RegistrationConfig {
                        max_per_source: 2,
                        ..registration_cfg()
                    },
                )
                .await
                .unwrap(),
            );
            let mut http = http;
            http.rate_limit_register = RateLimitRule {
                per_minute: 600,
                burst: 100,
            };
            let app = router::<TestProvider, Http<HttpClient>>(state, &http);

            for c in ["1", "2"] {
                let resp = app
                    .clone()
                    .oneshot(json_request(
                        "POST",
                        "/api/register",
                        "10.0.0.26",
                        &format!(r#"{{"commitment":"{c}"}}"#),
                    ))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }

            let resp = app
                .oneshot(json_request(
                    "POST",
                    "/api/register",
                    "10.0.0.26",
                    r#"{"commitment":"3"}"#,
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        // ---- concurrency shedding ------------------------------------------

        #[tokio::test]
        async fn requests_past_the_concurrency_ceiling_are_shed_with_503() {
            let mut http = test_http_config();
            http.max_concurrent_requests = 1;
            http.request_timeout = std::time::Duration::from_secs(30);
            let app = test_app(&http).await;

            // /ready blocks on a TCP connect to a closed port; on Windows
            // that is a real (if short) wait, long enough to hold the single
            // permit while a second request arrives.
            let slow = tokio::spawn({
                let app = app.clone();
                async move {
                    app.oneshot(request_from("GET", "/ready", "10.0.0.30", Body::empty()))
                        .await
                        .unwrap()
                        .status()
                }
            });

            tokio::task::yield_now().await;

            // Fire a burst; at least one must be shed while the permit is
            // held. (Asserting "exactly one" would be a race, not a test.)
            let mut shed = false;
            for _ in 0..20 {
                let status = app
                    .clone()
                    .oneshot(request_from("GET", "/health", "10.0.0.31", Body::empty()))
                    .await
                    .unwrap()
                    .status();
                if status == StatusCode::SERVICE_UNAVAILABLE {
                    shed = true;
                    break;
                }
            }
            let _ = slow.await;
            assert!(shed, "a 1-permit budget must shed a concurrent request");
        }
    }
}
