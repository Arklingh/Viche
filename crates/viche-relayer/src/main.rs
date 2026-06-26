//! `viche-relayer` — gasless ZK voting relayer (Axum + alloy).
//!
//! ## What this binary does
//!
//! 1. Loads config from env (`RELAYER_PRIVATE_KEY`, `RPC_URL`,
//!    `VOTING_MANAGER_ADDRESS`, listen addr/port).
//! 2. Builds an alloy provider with the wallet filler so it can both read
//!    chain state and sign+broadcast transactions from the relayer EOA.
//! 3. Starts an Axum server exposing:
//!    - `GET  /health`                — liveness probe.
//!    - `GET  /api/polls`             — list poll metadata.
//!    - `GET  /api/polls/:id`         — fetch one poll.
//!    - `GET  /api/polls/:id/tally`   — fetch per-option tallies.
//!    - `POST /api/vote`              — accept a ZK proof + nullifier,
//!      broadcast `VotingManager.castVote`, and return the transaction hash.
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

#![forbid(unsafe_code)]

mod config;
mod contract;
mod error;
mod handlers;
mod queries;
mod relay;

use alloy::network::EthereumWallet;
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::{Client as HttpTlsClient, Http};

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
        "starting viche-relayer"
    );

    // 2. Build the alloy provider with wallet + recommended fillers (gas
    //    estimation, nonce management, chain-id fetch).
    //
    // The `PrivateKeySigner` must be wrapped in an `EthereumWallet` to
    // satisfy the `NetworkWallet<Ethereum>` bound required by the
    // `WalletFiller`. The `EthereumWallet::from(signer)` impl handles this.
    let rpc_url: url::Url = cfg.rpc_url.parse()?;
    let wallet: EthereumWallet = cfg.relayer_private_key.into();
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url);

    // 3. Build the Axum app and start the listener.
    let state = AppState {
        provider,
        voting_manager_address: cfg.voting_manager_address,
    };
    let app = router::<_, Http<HttpTlsClient>>(state);

    let listener = tokio::net::TcpListener::bind(cfg.listen_addr).await?;
    tracing::info!(addr = %cfg.listen_addr, "HTTP server listening");
    axum::serve(listener, app).await?;

    Ok(())
}
