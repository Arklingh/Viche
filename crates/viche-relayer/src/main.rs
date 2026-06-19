//! `viche-relayer` — gasless ZK voting relayer.
//!
//! Architecture (Phase 2):
//!
//! ```text
//!   browser wallet ----POST /api/vote---->  relayer
//!   (builds the proof                       ├── validate VoteRequest shape
//!    in-page via snarkjs wasm)              ├── (optionally) recheck the proof
//!                                           ├── sign castVote tx with relayer key
//!                                           └── broadcast via alloy provider
//!                                                 |
//!                                                 v
//!                                            VotingManager (chain)
//! ```
//!
//! The relayer pays gas so end users never need ETH. Trust model: the relayer
//! is trusted only for *delivery* — it cannot forge a vote (no valid proof)
//! and cannot double-vote on a voter's behalf (the nullifier is fixed by the
//! voter's secret + pollId). A voter who doesn't trust the relayer can always
//! fall back to submitting `castVote` directly from their own wallet.
//!
//! ## Phase 1 status
//!
//! This file is a minimal, well-typed stub so the workspace compiles. Phase 2
//! will:
//!
//!   1. Load config from env (RPC URL, relayer private key, VotingManager addr).
//!   2. Construct an alloy `ProviderBuilder` + `SignerSolver`.
//!   3. Bind a typed contract instance to `IVotingManager::castVote`.
//!   4. Expose `POST /api/vote` via Axum, validate the body, build + sign +
//!      broadcast the transaction, and return the tx hash.

#![forbid(unsafe_code)]

fn main() {
    // Intentionally minimal. Phase 2 replaces this with a tokio runtime that
    // boots the Axum server, wires up the alloy provider/signer, and serves
    // `/api/vote`.
    eprintln!(
        "viche-relayer: scaffold binary. Phase 2 will implement the Axum server \
         and alloy-backed castVote submission."
    );
    eprintln!("See crates/viche-relayer/src/main.rs for the planned architecture.");
}
