//! Core relay logic: accept a validated vote request, build the on-chain
//! transaction, sign it, and broadcast it via alloy.
//!
//! This module is deliberately separated from the Axum handler so the relay
//! logic can be unit-tested without standing up an HTTP server.

use alloy::contract::Error as ContractError;
use alloy::network::Ethereum;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::transports::{Transport, TransportError};
use viche_core::wire::{NullifierHash, Proof, VoteResponse, VoteStatus};

use crate::contract::IVotingManager;
use crate::contract::IVotingManager::IVotingManagerErrors;
use crate::error::RelayError;

/// Response for an admin (`createPoll`/`closePoll`) transaction.
///
/// Same "broadcast and return immediately" model as [`VoteResponse`] — see
/// [`submit_create_poll`]'s doc comment for why the assigned `pollId` isn't
/// part of this response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdminTxResponse {
    /// The broadcast transaction hash, hex-encoded.
    pub tx_hash: String,
    /// Lifecycle status — always `broadcast` today (see `submit_vote`'s docs
    /// on why the relayer doesn't wait for inclusion).
    pub status: VoteStatus,
}

/// Submit a vote on-chain.
///
/// 1. Build the `castVote` calldata from the request fields.
/// 2. Pre-simulate via `eth_call` so a *doomed* vote (already voted, poll
///    closed/expired/nonexistent, bad option, rejected proof) fails fast
///    with a 409 instead of silently burning relayer gas on a broadcast
///    that's going to revert anyway — see [`describe_known_revert`].
/// 3. Broadcast via the provider (which fills gas, nonce, chain ID and signs
///    with the relayer key — all handled by the alloy fillers).
/// 4. Return the transaction hash immediately (the relayer does NOT wait
///    for inclusion, keeping latency low).
///
/// # On-chain revert handling
///
/// The pre-simulation in step 2 is *advisory, not authoritative*: chain
/// state can still change between it and the broadcast in step 3 (e.g.
/// another vote with the same nullifier lands in between), so a transaction
/// that passed simulation can still revert once mined. Alloy's
/// `send_transaction` does not simulate again before broadcasting, and the
/// relayer does not wait for the receipt (see step 4), so a revert that
/// happens *after* passing pre-simulation is logged only when the receipt is
/// fetched separately — it is not surfaced as a hard error from this
/// function. This asymmetry (pre-simulation catches the common cases, a
/// late race can still slip through) is an accepted tradeoff for keeping
/// vote latency low; a stronger guarantee would need to wait for the
/// receipt, which the relayer deliberately doesn't do.
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

    // Pre-simulate (`eth_call`, no gas spent, no tx broadcast). Only a
    // *recognised* revert short-circuits here; anything else (an unrelated
    // RPC hiccup, or a revert reason we don't have a case for) falls through
    // to the real broadcast below, unchanged from before this existed.
    if let Err(sim_err) = call.call().await {
        if let Some(message) = describe_known_revert(&sim_err) {
            tracing::info!(
                poll_id = %poll_id,
                reason = %message,
                "vote pre-simulation reverted; not broadcasting"
            );
            return Err(RelayError::OnChainRevert(message));
        }
        tracing::debug!(
            poll_id = %poll_id,
            error = %sim_err,
            "vote pre-simulation failed with an unrecognised error; broadcasting anyway"
        );
    }

    // Broadcast. The provider's fillers (gas, nonce, chain-id, wallet)
    // prepare the transaction before sending.
    let pending = call.send().await?;

    // Grab the hash immediately — we don't wait for mining.
    let tx_hash = pending.tx_hash();
    let tx_hash_hex = format!("{tx_hash:#x}");

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

/// Submit a `createPoll` transaction on-chain, signed by the configured
/// **admin** key (`Config::admin_private_key` — deliberately not the
/// relayer's vote-relay key; see that field's doc comment).
///
/// Same broadcast-and-return model as [`submit_vote`]: the assigned
/// `pollId` is a Solidity return value, only observable once the
/// transaction is mined, so it can't be part of this response. Callers
/// should poll `GET /api/polls` (or the tx receipt) to discover the new id.
///
/// # Errors
///
/// The contract reverts with `Unauthorized()` if `admin_provider`'s wallet
/// isn't `VotingManager.owner`, or `InvalidNumOptions()` /
/// `InvalidDeadline()` for malformed poll parameters — none of these are
/// pre-simulated (same tradeoff as `submit_vote`; see its doc comment).
pub async fn submit_create_poll<P, T>(
    admin_provider: P,
    contract_address: Address,
    merkle_root: B256,
    num_options: U256,
    deadline: U256,
    metadata_uri: String,
) -> Result<AdminTxResponse, RelayError>
where
    P: Provider<T, Ethereum>,
    T: Transport + Clone,
{
    let contract = IVotingManager::new(contract_address, &admin_provider);
    let call = contract.createPoll(merkle_root, num_options, deadline, metadata_uri);
    let pending = call.send().await?;

    let tx_hash = pending.tx_hash();
    let tx_hash_hex = format!("{tx_hash:#x}");

    tracing::info!(
        tx_hash = %tx_hash_hex,
        num_options = %num_options,
        "createPoll transaction broadcast"
    );

    Ok(AdminTxResponse {
        tx_hash: tx_hash_hex,
        status: VoteStatus::Broadcast,
    })
}

/// Submit a `closePoll` transaction on-chain, signed by the admin key.
///
/// # Errors
///
/// Reverts with `Unauthorized()` (not the owner) or `PollDoesNotExist(uint256)`.
pub async fn submit_close_poll<P, T>(
    admin_provider: P,
    contract_address: Address,
    poll_id: U256,
) -> Result<AdminTxResponse, RelayError>
where
    P: Provider<T, Ethereum>,
    T: Transport + Clone,
{
    let contract = IVotingManager::new(contract_address, &admin_provider);
    let call = contract.closePoll(poll_id);
    let pending = call.send().await?;

    let tx_hash = pending.tx_hash();
    let tx_hash_hex = format!("{tx_hash:#x}");

    tracing::info!(
        poll_id = %poll_id,
        tx_hash = %tx_hash_hex,
        "closePoll transaction broadcast"
    );

    Ok(AdminTxResponse {
        tx_hash: tx_hash_hex,
        status: VoteStatus::Broadcast,
    })
}

/// Decode a `castVote` simulation failure into a human-readable message —
/// but only for the errors that path can actually revert with. Returns
/// `None` for anything else: an unrecognised/undecodable revert, or a
/// non-revert error (RPC timeout, connection refused, ...). That `None`
/// case is deliberately treated by the caller as "not conclusive", not as
/// "definitely fine" — see [`submit_vote`].
///
/// Decodes against the real ABI (`IVotingManagerErrors`, generated by the
/// `sol!` macro in `contract.rs`) rather than hand-computed 4-byte
/// selectors — a typo in a hand-typed selector fails silently at runtime
/// (simply never matches), whereas a typo in the Solidity signature here
/// fails to compile.
fn describe_known_revert(err: &ContractError) -> Option<String> {
    let ContractError::TransportError(rpc_err) = err else {
        return None;
    };
    let payload = rpc_err.as_error_resp()?;
    let decoded = payload.as_decoded_error::<IVotingManagerErrors>(false)?;

    match decoded {
        IVotingManagerErrors::AlreadyVoted(_) => {
            Some("you have already voted in this poll".to_string())
        }
        IVotingManagerErrors::PollNotActive(_) => {
            Some("this poll is not currently active".to_string())
        }
        IVotingManagerErrors::PollEnded(e) => {
            Some(format!("voting has closed for poll {}", e.pollId))
        }
        IVotingManagerErrors::PollDoesNotExist(e) => {
            Some(format!("poll {} does not exist", e.pollId))
        }
        IVotingManagerErrors::InvalidVoteOption(_) => {
            Some("the selected option is not valid for this poll".to_string())
        }
        IVotingManagerErrors::InvalidProof(_) => Some("the submitted proof was rejected".to_string()),
        // Unauthorized/InvalidDeadline/InvalidNumOptions are createPoll/
        // closePoll-only — castVote can't revert with them. Not this
        // function's job to handle (see the admin submit_* functions).
        IVotingManagerErrors::Unauthorized(_)
        | IVotingManagerErrors::InvalidDeadline(_)
        | IVotingManagerErrors::InvalidNumOptions(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolInterface;
    use alloy::transports::RpcError;
    use alloy_json_rpc::ErrorPayload;

    /// Build a synthetic `alloy::contract::Error` shaped exactly like what
    /// alloy hands back for a reverted `eth_call`: a JSON-RPC error response
    /// whose `data` field is the revert bytes as a `0x`-prefixed hex string.
    /// This is the real decode path (`as_error_resp` -> `as_decoded_error`),
    /// just fed a payload we constructed instead of one a live node sent —
    /// no anvil / network access needed to test `describe_known_revert`.
    fn revert_error(err: IVotingManagerErrors) -> ContractError {
        let data = err.abi_encode();
        let hex = alloy::primitives::hex::encode_prefixed(data);
        let raw = serde_json::value::to_raw_value(&hex).unwrap();
        let payload = ErrorPayload {
            code: 3,
            message: "execution reverted".to_string(),
            data: Some(raw),
        };
        ContractError::TransportError(RpcError::ErrorResp(payload))
    }

    #[test]
    fn describe_known_revert_decodes_already_voted() {
        let err = revert_error(IVotingManagerErrors::AlreadyVoted(
            crate::contract::IVotingManager::AlreadyVoted {
                nullifierHash: B256::ZERO,
            },
        ));
        let msg = describe_known_revert(&err).unwrap();
        assert!(msg.contains("already voted"), "got: {msg}");
    }

    #[test]
    fn describe_known_revert_decodes_invalid_proof() {
        let err = revert_error(IVotingManagerErrors::InvalidProof(
            crate::contract::IVotingManager::InvalidProof {},
        ));
        let msg = describe_known_revert(&err).unwrap();
        assert!(msg.contains("proof"), "got: {msg}");
    }

    #[test]
    fn describe_known_revert_decodes_poll_not_active() {
        let err = revert_error(IVotingManagerErrors::PollNotActive(
            crate::contract::IVotingManager::PollNotActive {
                pollId: U256::from(7u64),
            },
        ));
        let msg = describe_known_revert(&err).unwrap();
        assert!(msg.contains("not currently active"), "got: {msg}");
    }

    #[test]
    fn describe_known_revert_decodes_poll_ended_with_id() {
        let err = revert_error(IVotingManagerErrors::PollEnded(
            crate::contract::IVotingManager::PollEnded {
                pollId: U256::from(42u64),
            },
        ));
        let msg = describe_known_revert(&err).unwrap();
        assert!(msg.contains("42"), "got: {msg}");
    }

    #[test]
    fn describe_known_revert_decodes_poll_does_not_exist_with_id() {
        let err = revert_error(IVotingManagerErrors::PollDoesNotExist(
            crate::contract::IVotingManager::PollDoesNotExist {
                pollId: U256::from(99u64),
            },
        ));
        let msg = describe_known_revert(&err).unwrap();
        assert!(msg.contains("99"), "got: {msg}");
    }

    #[test]
    fn describe_known_revert_decodes_invalid_vote_option() {
        let err = revert_error(IVotingManagerErrors::InvalidVoteOption(
            crate::contract::IVotingManager::InvalidVoteOption {
                voteOption: U256::from(5u64),
            },
        ));
        let msg = describe_known_revert(&err).unwrap();
        assert!(msg.contains("not valid"), "got: {msg}");
    }

    #[test]
    fn describe_known_revert_ignores_admin_only_errors() {
        // Unauthorized/InvalidDeadline/InvalidNumOptions can't happen via
        // castVote — describe_known_revert must not claim they can.
        let err = revert_error(IVotingManagerErrors::Unauthorized(
            crate::contract::IVotingManager::Unauthorized {},
        ));
        assert!(describe_known_revert(&err).is_none());
    }

    #[test]
    fn describe_known_revert_returns_none_for_undecodable_data() {
        let raw = serde_json::value::to_raw_value(&"0xdeadbeef").unwrap();
        let payload = ErrorPayload {
            code: 3,
            message: "execution reverted".to_string(),
            data: Some(raw),
        };
        let err = ContractError::TransportError(RpcError::ErrorResp(payload));
        assert!(describe_known_revert(&err).is_none());
    }

    #[test]
    fn describe_known_revert_returns_none_for_non_revert_transport_errors() {
        let err = ContractError::TransportError(RpcError::Transport(
            alloy::transports::TransportErrorKind::BackendGone,
        ));
        assert!(describe_known_revert(&err).is_none());
    }

    #[test]
    fn describe_known_revert_returns_none_for_non_transport_contract_errors() {
        // e.g. an ABI encode/decode error, unrelated to any on-chain revert.
        let err = ContractError::UnknownFunction("castVote".to_string());
        assert!(describe_known_revert(&err).is_none());
    }
}
