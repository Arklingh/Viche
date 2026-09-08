//! Read-only chain queries backing the relayer's poll-fetching endpoints.
//!
//! These functions wrap the `IVotingManager` view calls (`nextPollId`,
//! `getPoll`, `getOptionTally`) so the Axum handlers stay thin. They map
//! transport/contract errors into [`RelayError`] uniformly.

use std::collections::HashMap;

use alloy::network::Ethereum;
use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::transports::Transport;
use viche_core::wire::{PollData, TallyResponse};

use crate::contract::IVotingManager;
use crate::error::RelayError;

/// Fetch a single poll's core metadata from the contract, without
/// `metadata_uri` (see [`fetch_poll`], which fills that in separately).
///
/// Returns [`RelayError::Validation`] if the poll id does not exist on-chain
/// (the `getPoll` call reverts with `PollDoesNotExist`).
async fn fetch_poll_core<P, T>(
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
        metadata_uri: String::new(),
    })
}

/// Fetch every poll's `metadataUri`, keyed by poll id, from `PollCreated`
/// event logs.
///
/// `metadataUri` is never written to contract storage (`getPoll` doesn't
/// return it) — it only ever lands in this event, so recovering it means
/// scanning logs rather than making a view call. A scan failure (e.g. an RPC
/// node that prunes old logs) degrades to missing metadata rather than
/// failing the whole poll-list response, since metadata is a display nicety,
/// not data the contract itself depends on.
async fn fetch_metadata_uris<P, T>(provider: P, contract_address: Address) -> HashMap<U256, String>
where
    P: Provider<T, Ethereum> + Clone,
    T: Transport + Clone,
{
    let contract = IVotingManager::new(contract_address, &provider);
    match contract.PollCreated_filter().query().await {
        Ok(logs) => logs
            .into_iter()
            .map(|(ev, _log)| (ev.pollId, ev.metadataUri))
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to fetch PollCreated logs for metadata_uri");
            HashMap::new()
        }
    }
}

/// Fetch a single poll's metadata from the contract, including `metadata_uri`
/// recovered from its `PollCreated` event.
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
    let mut poll = fetch_poll_core(provider.clone(), contract_address, poll_id).await?;
    poll.metadata_uri = fetch_metadata_uris(provider, contract_address)
        .await
        .remove(&poll_id)
        .unwrap_or_default();
    Ok(poll)
}

/// Fetch all polls (1..=nextPollId-1) from the contract.
///
/// Poll ids start at 1 on-chain (`nextPollId` is the *next* id, not a count).
/// We iterate from 1 up to (but excluding) `nextPollId()`. A revert on any
/// individual `getPoll` (theoretically impossible since the poll was created)
/// is tolerated and skipped, keeping the list endpoint robust.
///
/// `metadata_uri` is fetched once as a single log scan (not per poll) and
/// merged in, rather than calling [`fetch_poll`] per id.
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
    let mut metadata = fetch_metadata_uris(provider.clone(), contract_address).await;

    let mut polls = Vec::new();
    let mut id = U256::from(1u64);
    while id < next_id {
        match fetch_poll_core(provider.clone(), contract_address, id).await {
            Ok(mut p) => {
                p.metadata_uri = metadata.remove(&id).unwrap_or_default();
                polls.push(p);
            }
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
    // Only `num_options`/`total_votes` are needed here, so skip the
    // `metadata_uri` log scan that `fetch_poll` would otherwise do.
    let poll = fetch_poll_core(provider.clone(), contract_address, poll_id).await?;

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
