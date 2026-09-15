//! `viche-relayer` — gasless ZK voting relayer (Axum + alloy).
//!
//! ## What this binary does
//!
//! 1. Loads config from env (`RELAYER_PRIVATE_KEY`, `RPC_URL`,
//!    `VOTING_MANAGER_ADDRESS`, listen addr/port).
//! 2. Builds an alloy provider with the wallet filler so it can both read
//!    chain state and sign+broadcast transactions from the relayer EOA.
//! 3. Starts an Axum server exposing:
//!    - `GET  /health`                — liveness probe (process is up).
//!    - `GET  /ready`                 — readiness probe: RPC reachable and
//!      the relayer wallet is still funded enough to pay for votes.
//!    - `GET  /api/polls`             — list poll metadata.
//!    - `GET  /api/polls/:id`         — fetch one poll.
//!    - `GET  /api/polls/:id/tally`   — fetch per-option tallies.
//!    - `POST /api/vote`              — accept a ZK proof + nullifier,
//!      broadcast `VotingManager.castVote`, and return the transaction hash.
//!    - `POST /api/admin/polls`       — owner-only, `Authorization: Bearer
//!      <ADMIN_API_KEY>`: broadcast `createPoll`.
//!    - `POST /api/admin/polls/:id/close` — owner-only: broadcast `closePoll`.
//!    - `POST /api/register`          — gated: submit an identity
//!      commitment ahead of the next poll (see `crate::registration`).
//!    - `GET  /api/admin/registrations/pending` — owner-only: the current
//!      unpublished commitment batch (`?detailed=true` for provenance).
//!    - `POST /api/admin/registrations/approve` — owner-only: approve
//!      pending commitments for inclusion in the next batch.
//!    - `POST /api/admin/registrations/reject`  — owner-only: discard
//!      pending commitments.
//!    - `POST /api/admin/registrations/snapshot` — owner-only: lock in the
//!      approved part of the batch so the admin's browser can build a
//!      Merkle tree from it.
//!    - `POST /api/admin/registrations/publish`  — owner-only: store the
//!      resulting root -> commitment-list mapping for voters to fetch later.
//!    - `GET  /api/polls/:id/registrations` — public: the commitment list a
//!      poll's whitelist was built from, so a voter's browser can rebuild
//!      the tree and extract its own membership proof.
//!
//! ## Trust model
//!
//! The relayer pays gas so end users don't need ETH. It is trusted only for
//! *delivery* — it cannot forge a vote (no valid proof) and cannot
//! double-vote on a voter's behalf (the nullifier is fixed by the voter's
//! `secret` + `pollId`). Voters who don't trust the relayer can always
//! submit `castVote` directly from their own wallet.
//!
//! ```text
//!   browser wallet ----POST /api/vote---->  relayer
//!   (builds the proof                       ├── validate VoteRequest shape
//!    in-page via snarkjs wasm)              ├── sign castVote tx with relayer key
//!                                           └── broadcast via alloy provider
//!                                                 |
//!                                                 v
//!                                            VotingManager (chain)
//! ```
//!
//! The `/api/admin/*` routes are a *separate* trust boundary: they sign with
//! a dedicated `ADMIN_PRIVATE_KEY` (the `VotingManager` owner), gated by a
//! shared-secret `ADMIN_API_KEY`, so a compromised relayer gas wallet alone
//! can't create or close polls. This is one of two ways to administer
//! polls — the other is the admin's own wallet calling `createPoll`/
//! `closePoll` directly (see `viche-frontend`'s admin UI), which needs no
//! relayer involvement at all.
//!
//! ## Abuse resistance
//!
//! The relayer's ETH is an unauthenticated, shared spend budget, so three
//! independent guards sit in front of it, each configurable and each
//! defaulting to the restrictive setting:
//!
//! - **[`crate::middleware`]** — per-IP rate limits (strictest on the two
//!   endpoints that cost money or grow state), tight per-route body caps,
//!   a request timeout, an in-flight concurrency ceiling that sheds rather
//!   than queues, an explicit CORS allowlist, and JSON-API security headers.
//! - **Gas ceiling** ([`crate::relay`]) — a fee estimate above
//!   `MAX_FEE_PER_GAS_GWEI` is rejected with a clear error instead of
//!   broadcast, so a gas spike can't empty the wallet unattended.
//! - **[`crate::eligibility`] + [`crate::registration`]** — `/api/register`
//!   is gated, capped per source and per batch, and (by default) requires
//!   explicit admin approval before a commitment can enter an electorate.
//!
//! ## Deployment topology
//!
//! ```text
//!   browser ──TLS──> reverse proxy ──HTTP──> viche-relayer
//!                     │  /            SPA (Trunk build)
//!                     └─ /api, /health, /ready  -> relayer :3000
//! ```
//!
//! Same-origin by design, which is why CORS defaults to allowing nothing.
//! If the proxy is present, set `TRUST_PROXY_HEADERS=true` and
//! `TRUSTED_PROXY_HOPS` to the number of proxies you control — otherwise
//! every request appears to come from the proxy and shares one rate-limit
//! bucket. See [`crate::middleware`] for why that is off by default.

#![forbid(unsafe_code)]

mod config;
mod contract;
mod eligibility;
mod error;
mod handlers;
mod middleware;
mod queries;
mod ratelimit;
mod registration;
mod relay;

use std::sync::Arc;

use alloy::network::EthereumWallet;
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::{Client as HttpTlsClient, Http};

use crate::registration::RegistrationStore;

use crate::config::Config;
use crate::handlers::{router, AppState};

/// Entry point. Errors here are fatal — they mean misconfiguration.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,viche_relayer=debug".into()),
        )
        .init();

    // 1. Load config.
    let cfg = Config::from_env()?;
    tracing::info!(
        rpc_url = %cfg.rpc_url,
        voting_manager = %cfg.voting_manager_address,
        listen = %cfg.listen_addr,
        relayer_addr = ?cfg.relayer_private_key.address(),
        admin_addr = ?cfg.admin_private_key.address(),
        "starting viche-relayer"
    );

    // 2. Build the alloy providers with wallet + recommended fillers (gas
    //    estimation, nonce management, chain-id fetch) — one for the
    //    relayer's vote-relay key, one for the admin (poll-owner) key. Two
    //    separate wallets so a compromised relayer key alone can't sign
    //    admin transactions.
    //
    // The `PrivateKeySigner` must be wrapped in an `EthereumWallet` to
    // satisfy the `NetworkWallet<Ethereum>` bound required by the
    // `WalletFiller`. The `EthereumWallet::from(signer)` impl handles this.
    let rpc_url: url::Url = cfg.rpc_url.parse()?;
    let relayer_address = cfg.relayer_private_key.address();
    let wallet: EthereumWallet = cfg.relayer_private_key.into();
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.clone());

    let admin_wallet: EthereumWallet = cfg.admin_private_key.into();
    let admin_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(admin_wallet)
        .on_http(rpc_url);

    // 3. Load the voter-registration store (see `crate::registration`).
    //    A corrupt file is fatal on purpose: starting empty would silently
    //    wipe the registry, which is strictly worse than not starting.
    let registrations = Arc::new(
        RegistrationStore::load(cfg.registrations_file.clone(), &cfg.registration).await?,
    );

    // 4. Install the registration eligibility gate (see `crate::eligibility`).
    let eligibility = crate::eligibility::build_policy(&cfg.registration)?;

    tracing::info!(
        eligibility = eligibility.name(),
        require_approval = cfg.registration.require_approval,
        max_per_source = cfg.registration.max_per_source,
        max_pending = cfg.registration.max_pending,
        max_fee_gwei = %crate::relay::format_gwei(cfg.gas.max_fee_per_gas_wei),
        max_concurrent = cfg.http.max_concurrent_requests,
        timeout_secs = cfg.http.request_timeout.as_secs(),
        trust_proxy = cfg.http.trust_proxy_headers,
        cors_origins = cfg.http.cors_allowed_origins.len(),
        "relayer guards configured"
    );

    // 5. Build the Axum app and start the listener.
    let state = AppState {
        provider,
        admin_provider,
        voting_manager_address: cfg.voting_manager_address,
        admin_api_key: cfg.admin_api_key,
        registrations,
        eligibility,
        relayer_address,
        gas: cfg.gas.clone(),
        health: cfg.health.clone(),
    };
    let app = router::<_, Http<HttpTlsClient>>(state, &cfg.http);

    let listener = tokio::net::TcpListener::bind(cfg.listen_addr).await?;
    tracing::info!(addr = %cfg.listen_addr, "HTTP server listening");

    // `into_make_service_with_connect_info` is what makes the socket peer
    // address visible to the client-IP middleware; without it every request
    // would fall back to the shared "unknown" rate-limit bucket.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
