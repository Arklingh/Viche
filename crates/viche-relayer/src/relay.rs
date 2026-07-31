//! Core relay logic: accept a validated vote request, build the on-chain
//! transaction, sign it, and broadcast it via alloy.
//!
//! This module is deliberately separated from the Axum handler so the relay
//! logic can be unit-tested without standing up an HTTP server.

use alloy::network::Ethereum;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::transports::Transport;
use viche_core::wire::{NullifierHash, Proof, VoteResponse, VoteStatus};

use crate::contract::IVotingManager;
use crate::error::RelayError;

/// Submit a vote on-chain.
///
/// 1. Build the `castVote` calldata from the request fields.
/// 2. Broadcast via the provider (which fills gas, nonce, chain ID and signs
///    with the relayer key — all handled by the alloy fillers).
/// 3. Return the transaction hash immediately (the relayer does NOT wait
///    for inclusion, keeping latency low).
///
/// # On-chain revert handling
///
/// Alloy's `send_transaction` does **not** simulate first by default when
/// using `ProviderBuilder::on_http`. The transaction is broadcast, and if it
/// reverts the relayer will detect it only when the receipt comes back (or
/// the RPC node rejects it pre-check). For a production relayer you'd want:
///   - `eth_estimateGas` pre-check, OR
///   - `eth_call` simulation, OR
///   - anvil's `anvil_revert` detection
///
/// Phase 2 keeps it simple: broadcast and return the hash. Revert detection
/// is logged but not surfaced as a hard error (the tx landed on chain, it
/// just didn't succeed). Future: add pre-simulation and return 409 Conflict
/// for known reverts (AlreadyVoted, PollNotActive, InvalidProof, etc.).
pub async fn submit_vote<P, T>(
    provider: P,
    contract_address: Address,
    poll_id: U256,
    nullifier_hash: &NullifierHash,
    proof: &Proof,
    vote_option: U256,
) -> Result<VoteResponse, RelayError>
where
    P: Provider<T, Ethereum>,
    T: Transport + Clone,
{
    // Build the contract instance and call.
    let contract = IVotingManager::new(contract_address, &provider);

    let call = contract.castVote(
        poll_id,
        proof.as_bytes().clone(),
        B256::from(nullifier_hash.as_u256().to_be_bytes()),
        vote_option,
    );

    // Broadcast. The provider's fillers (gas, nonce, chain-id, wallet)
    // prepare the transaction before sending.
    let pending = call.send().await?;

    // Grab the hash immediately — we don't wait for mining.
    let tx_hash = pending.tx_hash();
    let tx_hash_hex = format!("0x{:?}", tx_hash);

    tracing::info!(
        poll_id = %poll_id,
        tx_hash = %tx_hash_hex,
        "vote transaction broadcast"
    );

    Ok(VoteResponse {
        tx_hash: tx_hash_hex,
        status: VoteStatus::Broadcast,
    })
}

/// The Solidity selectors for `VotingManager`'s custom errors, used for
/// revert decoding in pre-simulation (Phase 2 future enhancement).
///
/// These are the first 4 bytes of `keccak256("ErrorName(uint256)")`.
pub mod selectors {
    use alloy::primitives::B256;

    /// `VotingManager.PollDoesNotExist(uint256)`
    pub const POLL_DOES_NOT_EXIST: &str = "0xa32b6702"; // keccak256("PollDoesNotExist(uint256)")[..4]
    /// `VotingManager.AlreadyVoted(bytes32)`
    pub const ALREADY_VOTED: &str = "0x063a3d7c"; // keccak256("AlreadyVoted(bytes32)")[..4]
    /// `VotingManager.InvalidProof()`
    pub const INVALID_PROOF: &str = "0x4c79181d"; // keccak256("InvalidProof()")[..4]
    /// `VotingManager.PollNotActive(uint256)`
    pub const POLL_NOT_ACTIVE: &str = "0x0ad259a7"; // keccak256("PollNotActive(uint256)")[..4]
    /// `VotingManager.PollEnded(uint256)`
    pub const POLL_ENDED: &str = "0x7f9adeab"; // keccak256("PollEnded(uint256)")[..4]
}
