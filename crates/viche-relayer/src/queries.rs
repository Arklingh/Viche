//! Read-only chain queries backing the relayer's poll-fetching endpoints.
//!
//! These functions wrap the `IVotingManager` view calls (`nextPollId`,
//! `getPoll`, `getOptionTally`) so the Axum handlers stay thin. They map
//! transport/contract errors into [`RelayError`] uniformly.

use alloy::network::Ethereum;
use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::transports::Transport;
use viche_core::wire::{PollData, TallyResponse};

use crate::contract::IVotingManager;
use crate::error::RelayError;

/// Fetch a single poll's metadata from the contract.
///
/// Returns [`RelayError::Validation`] if the poll id does not exist on-chain
/// (the `getPoll` call reverts with `PollDoesNotExist`).
pub async fn fetch_poll<P, T>(
    provider: P,
    contract_address: Address,
    poll_id: U256,
) -> Result<PollData, RelayError>
where
    P: Provider<T, Ethereum> + Clone,
    T: Transport + Clone,
{
    let contract = IVotingManager::new(contract_address, &provider);

    let result = contract.getPoll(poll_id).call().await;

    let r = match result {
        Ok(r) => r,
        Err(e) => {
            // getPoll reverts with PollDoesNotExist(uint256) for unknown ids.
            return Err(RelayError::Validation(format!(
                "poll {} not found: {}",
                poll_id, e
            )));
        }
    };

    // The sol!-generated `getPollReturn` exposes one field per return value.
    Ok(PollData {
        poll_id,
        merkle_root: U256::from_be_bytes(r.merkleRoot.into()),
        deadline: r.deadline,
        num_options: r.numOptions,
        total_votes: r.totalVotes,
        active: r.active,
    })
}

/// Fetch all polls (1..=nextPollId-1) from the contract.
///
/// Poll ids start at 1 on-chain (`nextPollId` is the *next* id, not a count).
/// We iterate from 1 up to (but excluding) `nextPollId()`. A revert on any
/// individual `getPoll` (theoretically impossible since the poll was created)
/// is tolerated and skipped, keeping the list endpoint robust.
pub async fn fetch_all_polls<P, T>(
    provider: P,
    contract_address: Address,
) -> Result<Vec<PollData>, RelayError>
where
    P: Provider<T, Ethereum> + Clone,
    T: Transport + Clone,
{
    let contract = IVotingManager::new(contract_address, &provider);

    let next_id = contract.nextPollId().call().await?._0;

    let mut polls = Vec::new();
    let mut id = U256::from(1u64);
    while id < next_id {
        match fetch_poll(provider.clone(), contract_address, id).await {
            Ok(p) => polls.push(p),
            Err(e) => {
                tracing::warn!(poll_id = %id, error = %e, "skipping poll during list fetch");
            }
        }
        id += U256::from(1u64);
    }

    Ok(polls)
}

/// Fetch the per-option tallies for a poll.
///
/// Issues `numOptions` `getOptionTally` calls. Returns
/// [`RelayError::Validation`] if the poll does not exist.
pub async fn fetch_tally<P, T>(
    provider: P,
    contract_address: Address,
    poll_id: U256,
) -> Result<TallyResponse, RelayError>
where
    P: Provider<T, Ethereum> + Clone,
    T: Transport + Clone,
{
    let poll = fetch_poll(provider.clone(), contract_address, poll_id).await?;

    let contract = IVotingManager::new(contract_address, &provider);

    let num = poll.num_options;
    let mut option_tallies = Vec::new();
    let mut i = U256::ZERO;
    while i < num {
        let tally = contract
            .getOptionTally(poll_id, i)
            .call()
            .await
            .map_err(|e| RelayError::Validation(format!("tally fetch failed: {}", e)))?;
        option_tallies.push(tally._0);
        i += U256::from(1u64);
    }

    Ok(TallyResponse {
        poll_id,
        option_tallies,
        total_votes: poll.total_votes,
    })
}
