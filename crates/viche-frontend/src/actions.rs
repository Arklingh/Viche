//! Async orchestration: wallet connect, poll fetches, and the vote pipeline.
//!
//! Each action spawns a `wasm-bindgen-futures` task that drives the relevant
//! module and writes results back into the shared [`AppSignals`]. Components
//! stay declarative — they call these actions in event handlers and read the
//! resulting signal updates.

use alloy_primitives::{Bytes, FixedBytes, U256};
use leptos::{spawn_local, SignalGet, SignalSet, SignalUpdate, SignalGetUntracked};
use viche_core::wire::{NullifierHash, Proof, PublishRegistrationRequest, RegisterRequest, VoteRequest};

use crate::api::ApiClient;
use crate::config::relayer_url;
use crate::state::{AdminTxPhase, AppSignals, RegisterPhase, VotePhase, WhitelistBuildPhase};
use crate::wallet::Wallet;

/// Connect (or re-query) the injected wallet.
pub fn connect_wallet(signals: AppSignals) {
    spawn_local(async move {
        let wallet = match crate::wallet::detect() {
            Some(w) => w,
            None => {
                signals.wallet_error("No EIP-1193 wallet found. Install MetaMask or similar.");
                return;
            }
        };

        // Request accounts (triggers the connect prompt).
        let accounts = match wallet.request_accounts().await {
            Ok(a) => a,
            Err(e) => {
                signals.wallet_error(format!("Connection rejected: {}", e));
                return;
            }
        };
        let address: Option<String> = accounts.into_iter().next();

        let chain_id: Option<String> = wallet.chain_id().await.ok();

        // Attach listeners so the UI updates on account/chain changes.
        {
            let s = signals.clone();
            wallet
                .on_accounts_changed(move |accts| {
                    let new_addr: Option<String> = accts.into_iter().next();
                    s.wallet.update(|w| w.address = new_addr);
                    // A different account is, as far as this app can tell, a
                    // different person: drop both credentials rather than let
                    // the new account inherit the old one's secret or admin
                    // key. The secret is only dropped from memory — it stays
                    // cached under its own address key.
                    s.secret_cleared();
                    s.clear_admin_api_key();
                    check_admin(s.clone());
                })
                .leak();
        }
        {
            let s = signals.clone();
            wallet
                .on_chain_changed(move |cid| {
                    s.wallet.update(|w| w.chain_id = Some(cid));
                })
                .leak();
        }

        match (address, chain_id) {
            (Some(addr), Some(cid)) => {
                signals.wallet_connected(addr, cid);
                check_admin(signals);
            }
            (Some(addr), None) => {
                signals.wallet_connected(addr, String::new());
                check_admin(signals);
            }
            _ => signals.wallet_error("Wallet returned no accounts."),
        }
    });
}

/// Check whether the connected wallet is the on-chain `VotingManager` owner,
/// and update `signals.is_admin` accordingly. A missing wallet, missing
/// contract address, or any RPC error is treated as "not admin" — the admin
/// page itself is purely a UX gate, so failing closed here just hides it.
pub fn check_admin(signals: AppSignals) {
    let address = match signals.wallet.get_untracked().address.clone() {
        Some(a) => a,
        None => {
            signals.is_admin.set(false);
            return;
        }
    };
    let contract = match crate::config::voting_manager_address() {
        Some(c) => c,
        None => {
            signals.is_admin.set(false);
            return;
        }
    };

    spawn_local(async move {
        let wallet = match crate::wallet::detect() {
            Some(w) => w,
            None => {
                signals.is_admin.set(false);
                return;
            }
        };
        signals.is_admin.set(is_owner(&wallet, &contract, &address).await);
    });
}

/// Query `owner()` on `contract` via `wallet` and compare it (case-insensitive)
/// to `address`. Any RPC or decode error is treated as "not the owner".
async fn is_owner(wallet: &Wallet, contract: &str, address: &str) -> bool {
    let data = crate::onchain::encode_owner();
    match wallet.eth_call(contract, &data).await {
        Ok(resp) => crate::onchain::decode_owner(&resp)
            .map(|owner| owner.eq_ignore_ascii_case(address))
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Everything needed to send an `onlyOwner` admin transaction, resolved
/// synchronously before any `spawn_local` — so a missing wallet/contract
/// never leaves the UI stuck in "Submitting".
struct AdminTxContext {
    wallet: Wallet,
    from: String,
    contract: String,
}

/// Resolve the connected wallet, its address, and the configured contract
/// address, or record a failure on `tx_signal` and return `None`.
fn resolve_admin_tx_context(
    signals: &AppSignals,
    tx_signal: leptos::RwSignal<crate::state::AdminTxState>,
) -> Option<AdminTxContext> {
    let from = match signals.wallet.get_untracked().address.clone() {
        Some(a) => a,
        None => {
            crate::state::admin_tx_failed(tx_signal, "Connect your wallet first.");
            return None;
        }
    };
    let contract = match crate::config::voting_manager_address() {
        Some(c) => c,
        None => {
            crate::state::admin_tx_failed(
                tx_signal,
                "Voting manager contract address is not configured.",
            );
            return None;
        }
    };
    let wallet = match crate::wallet::detect() {
        Some(w) => w,
        None => {
            crate::state::admin_tx_failed(tx_signal, "No EIP-1193 wallet found.");
            return None;
        }
    };
    Some(AdminTxContext {
        wallet,
        from,
        contract,
    })
}

/// Validate and parse the "Create Poll" form fields into `createPoll`'s
/// on-chain argument types. Pure (no I/O), so it fails synchronously and is
/// exercised directly by unit tests without a wallet or event loop.
fn validate_create_poll_input(
    merkle_root_input: &str,
    num_options_input: &str,
    deadline_input: &str,
) -> Result<(FixedBytes<32>, u64, u64), String> {
    let root = crate::onchain::parse_bytes32(merkle_root_input)
        .map_err(|e| format!("Invalid merkle root: {}", e))?;
    let num_options: u64 = num_options_input
        .trim()
        .parse()
        .ok()
        .filter(|n| *n >= 2)
        .ok_or_else(|| "Number of options must be an integer >= 2.".to_string())?;
    let deadline = crate::onchain::parse_datetime_local_unix(deadline_input)
        .ok_or_else(|| "Invalid voting deadline.".to_string())?;
    Ok((root, num_options, deadline))
}

/// Validate and parse the "Close Poll" poll id. Pure, see
/// [`validate_create_poll_input`].
fn validate_close_poll_input(poll_id: &str) -> Result<u64, String> {
    poll_id
        .trim()
        .parse()
        .map_err(|_| "Invalid poll id.".to_string())
}

/// Submit a `createPoll` transaction directly from the connected wallet.
///
/// `createPoll`/`closePoll` are `onlyOwner` on-chain, so unlike voting there
/// is no relayer/proof pipeline here: the admin's own wallet signs and pays
/// gas, and the contract itself rejects the call if the sender isn't the
/// owner.
pub fn submit_create_poll(
    signals: AppSignals,
    merkle_root_input: String,
    num_options_input: String,
    deadline_input: String,
    metadata_uri: String,
) {
    let tx_signal = signals.admin_create;
    crate::state::set_admin_tx_phase(tx_signal, AdminTxPhase::Submitting);

    let Some(ctx) = resolve_admin_tx_context(&signals, tx_signal) else {
        return;
    };
    let (root, num_options, deadline) = match validate_create_poll_input(
        &merkle_root_input,
        &num_options_input,
        &deadline_input,
    ) {
        Ok(v) => v,
        Err(e) => {
            crate::state::admin_tx_failed(tx_signal, e);
            return;
        }
    };

    spawn_local(async move {
        let data =
            crate::onchain::encode_create_poll(root, num_options, deadline, &metadata_uri);
        match ctx.wallet.send_transaction(&ctx.from, &ctx.contract, &data).await {
            Ok(tx_hash) => {
                crate::state::admin_tx_done(tx_signal, tx_hash);
                refresh_polls(signals);
            }
            Err(e) => {
                crate::state::admin_tx_failed(tx_signal, format!("Transaction failed: {}", e))
            }
        }
    });
}

/// Submit a `closePoll` transaction directly from the connected wallet.
pub fn submit_close_poll(signals: AppSignals, poll_id: String) {
    let tx_signal = signals.admin_close;
    crate::state::set_admin_tx_phase(tx_signal, AdminTxPhase::Submitting);

    let Some(ctx) = resolve_admin_tx_context(&signals, tx_signal) else {
        return;
    };
    let pid = match validate_close_poll_input(&poll_id) {
        Ok(p) => p,
        Err(e) => {
            crate::state::admin_tx_failed(tx_signal, e);
            return;
        }
    };

    spawn_local(async move {
        let data = crate::onchain::encode_close_poll(pid);
        match ctx.wallet.send_transaction(&ctx.from, &ctx.contract, &data).await {
            Ok(tx_hash) => {
                crate::state::admin_tx_done(tx_signal, tx_hash);
                refresh_polls(signals);
            }
            Err(e) => {
                crate::state::admin_tx_failed(tx_signal, format!("Transaction failed: {}", e))
            }
        }
    });
}

/// Fetch the poll list once on mount, if not already loaded.
pub fn fetch_polls_on_mount(signals: AppSignals) {
    if signals.polls.get_untracked().is_some() {
        return;
    }
    refresh_polls(signals);
}

/// Refresh the poll list from the relayer.
pub fn refresh_polls(signals: AppSignals) {
    signals.polls_error.set(None);
    let client = ApiClient::new(relayer_url());
    spawn_local(async move {
        match client.fetch_polls().await {
            Ok(list) => signals.polls.set(Some(list)),
            Err(e) => signals.polls_error.set(Some(format!("{}", e))),
        }
    });
}

/// Fetch a poll's tally into `current_tally`.
pub fn fetch_tally(signals: AppSignals, poll_id: String) {
    signals.current_tally.set(None);
    let client = ApiClient::new(relayer_url());
    spawn_local(async move {
        if let Ok(t) = client.fetch_tally(&poll_id).await {
            signals.current_tally.set(Some(t));
        }
    });
}

/// The full vote pipeline: witness -> prove -> submit.
pub fn cast_vote(signals: AppSignals, poll_id: String, merkle_root: String, option: usize) {
    signals.vote_reset();
    signals.vote_phase(VotePhase::Witness);

    spawn_local(async move {
        // 1. Resolve the voter's secret: cached per account, otherwise
        //    derived from a wallet signature (see `crate::secret`).
        let wallet_addr: String = match signals.wallet.get_untracked().address.clone() {
            Some(a) => a,
            None => {
                signals.vote_failed("Connect your wallet first.");
                return;
            }
        };
        let resolved = match crate::secret::resolve(&wallet_addr).await {
            Ok(s) => s,
            Err(e) => {
                signals.vote_failed(e.user_message());
                return;
            }
        };
        // Publishes any storage warning into `signals.secret`, which the vote
        // form renders as a banner. A warning here is never fatal: a
        // wallet-derived secret is reproducible even if it could not be
        // cached, which is the whole reason derivation replaced randomness.
        signals.secret_resolved(&resolved);
        let secret = resolved.value;

        // 2. Build the Merkle witness.
        let witness = match build_witness(&secret, &poll_id, &merkle_root).await {
            Ok(w) => w,
            Err(e) => {
                signals.vote_failed(format!("Witness build failed: {}", e));
                return;
            }
        };

        // 3. Generate the Groth16 proof.
        signals.vote_phase(VotePhase::Proving);
        let proof = match generate_proof(witness).await {
            Ok(p) => p,
            Err(e) => {
                signals.vote_failed(format!("Proof generation failed: {}", e));
                return;
            }
        };

        // 4. Build the VoteRequest and submit.
        signals.vote_phase(VotePhase::Submitting);

        let poll_u256 = match U256::from_str_radix(&poll_id, 10) {
            Ok(v) => v,
            Err(_) => {
                signals.vote_failed("Invalid poll id.");
                return;
            }
        };

        let proof_wrapped = match Proof::from_bytes(Bytes::from(proof.proof_bytes.to_vec())) {
            Ok(p) => p,
            Err(e) => {
                signals.vote_failed(format!("Invalid proof length: {}", e));
                return;
            }
        };

        let nullifier = match NullifierHash::try_from(proof.nullifier_hash) {
            Ok(n) => n,
            Err(e) => {
                signals.vote_failed(format!("Nullifier out of field: {}", e));
                return;
            }
        };

        let req = VoteRequest {
            poll_id: poll_u256,
            vote_option: U256::from(option as u64),
            nullifier_hash: nullifier,
            proof: proof_wrapped,
        };

        let client = ApiClient::new(relayer_url());
        match client.submit_vote(&req).await {
            Ok(resp) => {
                signals.vote_done(resp);
                fetch_tally(signals, poll_id);
            }
            Err(e) => {
                signals.vote_failed(format!("Relayer error: {}", e));
            }
        }
    });
}

// ---- voter secret actions -----------------------------------------------

/// Resolve the connected account's secret into `signals.secret`, prompting
/// for the derivation signature if it isn't cached yet.
///
/// Used by the backup panel so a voter can look at (and export) their secret
/// without first having to start a registration or a vote.
pub fn load_secret(signals: AppSignals) {
    let Some(address) = signals.wallet.get_untracked().address.clone() else {
        signals.secret_failed("Connect your wallet first.");
        return;
    };
    signals.secret_busy();
    spawn_local(async move {
        match crate::secret::resolve(&address).await {
            Ok(resolved) => signals.secret_resolved(&resolved),
            Err(e) => signals.secret_failed(e.user_message()),
        }
    });
}

/// Replace a legacy-random or imported secret with the wallet-derived one.
///
/// Destructive by design: it changes `Poseidon(secret)`, so any commitment
/// already registered under the old value stops matching. The panel that
/// calls this must have told the voter they will need to register again.
pub fn migrate_secret_to_wallet_derived(signals: AppSignals) {
    let Some(address) = signals.wallet.get_untracked().address.clone() else {
        signals.secret_failed("Connect your wallet first.");
        return;
    };
    signals.secret_busy();
    spawn_local(async move {
        match crate::secret::migrate_to_wallet_derived(&address).await {
            Ok(resolved) => {
                // Order matters: `secret_resolved` publishes the new value
                // and provenance, `secret_notice` then adds the message
                // without disturbing either.
                signals.secret_resolved(&resolved);
                signals.secret_notice(
                    "Switched to a wallet-derived secret. Your commitment has changed, so \
                     register again before the next poll is built.",
                );
            }
            Err(e) => signals.secret_failed(e.user_message()),
        }
    });
}

/// Restore a secret the voter pasted into the import box.
///
/// Synchronous: parsing and storing need neither the wallet nor the network,
/// so a bad paste is rejected instantly instead of after a signature prompt.
pub fn import_secret(signals: AppSignals, pasted: String) {
    let Some(address) = signals.wallet.get_untracked().address.clone() else {
        signals.secret_failed("Connect your wallet first.");
        return;
    };

    let parsed = match crate::secret::parse_backup(&pasted) {
        Ok(p) => p,
        Err(e) => {
            signals.secret_failed(e.user_message());
            return;
        }
    };

    // Importing a backup taken from a *different* account is legitimate (it
    // is how you move an identity to a new wallet) but it is also exactly
    // what a mis-paste looks like, so say so rather than silently accepting.
    let cross_account = parsed
        .address
        .as_deref()
        .filter(|backup_addr| !backup_addr.eq_ignore_ascii_case(&address))
        .map(|backup_addr| {
            format!(
                " Note: this backup was exported for {}, not the connected account.",
                crate::secret::short_address(backup_addr)
            )
        })
        .unwrap_or_default();

    match crate::secret::import(&address, parsed.secret) {
        Ok(resolved) => {
            signals.secret_resolved(&resolved);
            signals.secret_notice(format!(
                "Secret restored and cached for this account.{cross_account} Make sure its \
                 commitment is registered before you try to vote."
            ));
        }
        Err(e) => signals.secret_failed(e.user_message()),
    }
}

/// Delete the cached secret for the connected account.
pub fn forget_secret(signals: AppSignals) {
    let Some(address) = signals.wallet.get_untracked().address.clone() else {
        signals.secret_failed("Connect your wallet first.");
        return;
    };
    match crate::secret::forget(&address) {
        Ok(()) => {
            signals.secret_cleared();
            signals.secret_notice(
                "Cached secret deleted from this browser. A wallet-derived secret comes back \
                 with one signature; anything else is now only in your backup.",
            );
        }
        Err(e) => signals.secret_failed(e.user_message()),
    }
}

// ---- helpers ------------------------------------------------------------

/// Get a ready circomlibjs Poseidon bridge, or an actionable error if the
/// WASM crypto engine (loaded from `index.html`) hasn't finished loading yet.
fn ready_poseidon() -> anyhow::Result<crate::crypto::CircomlibPoseidon> {
    let window = web_sys::window()
        .ok_or_else(|| anyhow::anyhow!("No browser window context found"))?;

    let js_val = js_sys::Reflect::get(&window, &"__VICHE_CRYPTO_READY__".into())
        .map_err(|_| anyhow::anyhow!("Failed to search window variables"))?;

    // Verify the flag is set and evaluates to true
    if js_val.is_undefined() || js_val.is_null() || !js_val.as_bool().unwrap_or(false) {
        return Err(anyhow::anyhow!(
            "Web3 Cryptographic engine is loading. Please wait 3 seconds and try again."
        ));
    }

    crate::crypto::CircomlibPoseidon::new()
        .map_err(|e| anyhow::anyhow!("Crypto engine not ready: {:?}", e))
}

/// Insert `commitments` (already-hashed leaves, in order) into a fresh tree.
///
/// Shared by [`build_witness`] (a voter locating their own path) and
/// [`build_whitelist_from_registrations`] (the admin computing a root to
/// create the next poll with) — both must produce the *same* root from the
/// same list, so the tree-construction logic lives in exactly one place.
fn build_tree_from_commitments(
    poseidon: &crate::crypto::CircomlibPoseidon,
    commitments: &[U256],
) -> viche_core::merkle::SparseMerkleTree<crate::crypto::CircomlibPoseidon, { viche_core::merkle::DEFAULT_DEPTH }> {
    let mut tree = viche_core::merkle::SparseMerkleTree::new(poseidon);
    for c in commitments {
        tree.insert(poseidon, *c);
    }
    tree
}

/// Build the Merkle witness for the voter's secret.
///
/// Fetches the poll's registered commitment list from the relayer (see
/// `GET /api/polls/:id/registrations`), rebuilds the same tree the admin
/// built when creating the poll, and locates the caller's own leaf in it —
/// see [`register_to_vote`] for how a commitment gets into that list in the
/// first place.
async fn build_witness(
    secret: &U256,
    poll_id: &str,
    merkle_root: &str,
) -> anyhow::Result<crate::proofgen::VoteWitness> {
    use viche_core::poseidon::PoseidonProvider;

    let poseidon = ready_poseidon()?;

    let client = ApiClient::new(relayer_url());
    let commitments = client.fetch_poll_registrations(poll_id).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to fetch this poll's registered voters from the relayer: {}",
            e
        )
    })?;

    let my_commitment = poseidon.hash_1(secret)?;
    let idx = commitments
        .iter()
        .position(|c| *c == my_commitment)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Your voter secret's commitment is not in this poll's whitelist. Register on \
                 the \"Register to Vote\" page before the admin builds the next poll."
            )
        })?;

    let tree = build_tree_from_commitments(&poseidon, &commitments);
    let proof = tree.proof(idx as u64);
    let root = tree.root();

    let on_chain = U256::from_str_radix(merkle_root.trim_start_matches("0x"), 16)
        .or_else(|_| U256::from_str_radix(merkle_root, 10))?;
    if root != on_chain {
        tracing_warn(format!(
            "Recomputed Merkle root {} does not match on-chain root {}. The proof may be rejected.",
            root, on_chain
        ));
    }

    let vote_id = U256::from_str_radix(poll_id, 10).unwrap_or_default();
    let nullifier = poseidon.hash_2(secret, &vote_id)?;

    Ok(crate::proofgen::VoteWitness {
        secret: *secret,
        path_elements: proof.path_elements,
        path_indices: proof.path_indices,
        vote_id,
        merkle_root: root,
        nullifier_hash: nullifier,
    })
}

/// Submit the connected wallet's identity commitment ahead of the next poll.
///
/// Public and permissionless — see the module doc on
/// `viche_relayer::registration` for why this is safe to leave open. The
/// commitment is derived from the same per-wallet secret [`build_witness`]
/// later uses to prove membership, so registering and voting always agree
/// on the same identity.
pub fn register_to_vote(signals: AppSignals) {
    use viche_core::poseidon::PoseidonProvider;

    signals.register_phase(RegisterPhase::Submitting);

    spawn_local(async move {
        let wallet_addr: String = match signals.wallet.get_untracked().address.clone() {
            Some(a) => a,
            None => {
                signals.register_failed("Connect your wallet first.");
                return;
            }
        };
        let resolved = match crate::secret::resolve(&wallet_addr).await {
            Ok(s) => s,
            Err(e) => {
                signals.register_failed(e.user_message());
                return;
            }
        };
        signals.secret_resolved(&resolved);
        let secret = resolved.value;

        let poseidon = match ready_poseidon() {
            Ok(p) => p,
            Err(e) => {
                signals.register_failed(e.to_string());
                return;
            }
        };
        let commitment = match poseidon.hash_1(&secret) {
            Ok(c) => c,
            Err(e) => {
                signals.register_failed(format!("Failed to compute commitment: {}", e));
                return;
            }
        };

        let client = ApiClient::new(relayer_url());
        match client.register(&RegisterRequest { commitment }).await {
            Ok(resp) => signals.register_done(resp.total_pending),
            Err(e) => signals.register_failed(format!("Relayer error: {}", e)),
        }
    });
}

/// Snapshot the currently-pending registrations, build a Merkle tree from
/// them client-side, and publish the resulting root back to the relayer.
///
/// On success, `signals.whitelist_build`'s `merkle_root` holds the freshly
/// computed root (0x-prefixed, 32 bytes) — the admin UI copies it into the
/// create-poll form. Requires the relayer's `ADMIN_API_KEY` (a separate
/// credential from the wallet-based admin gate — see [`crate::admin_key`]),
/// passed in from the in-memory session signal rather than read from storage.
pub fn build_whitelist_from_registrations(signals: AppSignals, admin_api_key: String) {
    signals.whitelist_build_phase(WhitelistBuildPhase::Building);

    if !crate::admin_key::is_usable(&admin_api_key) {
        // Fail here rather than send an empty bearer token: the relayer
        // would answer 401 and the admin would be left guessing whether the
        // key is wrong or simply absent after a page reload (which now drops
        // it by design).
        signals.whitelist_build_failed(ADMIN_KEY_MISSING);
        return;
    }

    spawn_local(async move {
        let poseidon = match ready_poseidon() {
            Ok(p) => p,
            Err(e) => {
                signals.whitelist_build_failed(e.to_string());
                return;
            }
        };

        let client = ApiClient::new(relayer_url());
        let commitments = match client.snapshot_registrations(&admin_api_key).await {
            Ok(c) => c,
            // The relayer refuses to drain a non-empty batch with nothing
            // approved, because an empty whitelist means a poll nobody can
            // vote in. Point the admin at the review step rather than showing
            // them a raw HTTP error for a routine, fixable situation.
            Err(crate::api::SnapshotFailure::NothingApproved(detail)) => {
                signals.whitelist_build_failed(nothing_approved_message(
                    signals.pending_registrations.get_untracked(),
                    &detail,
                ));
                return;
            }
            Err(crate::api::SnapshotFailure::Other(e)) => {
                signals.whitelist_build_failed(format!("Failed to snapshot registrations: {}", e));
                return;
            }
        };
        // `snapshot` already drained the server-side pending list, so the
        // panel's count is stale as of right now — update it locally instead
        // of making a redundant round trip just to confirm it's zero. The
        // reviewed list goes with it: leaving it on screen would invite the
        // admin to "approve" entries that no longer exist.
        signals.pending_registrations.set(Some(0));
        signals.pending_commitments.set(Some(Vec::new()));
        if commitments.is_empty() {
            signals.whitelist_build_failed("No pending registrations to build a whitelist from.");
            return;
        }

        let tree = build_tree_from_commitments(&poseidon, &commitments);
        let root = tree.root();
        let root_hex = format!("0x{}", alloy_primitives::hex::encode(root.to_be_bytes::<32>()));

        let publish_result = client
            .publish_registration(&admin_api_key, &PublishRegistrationRequest { merkle_root: root })
            .await;
        match publish_result {
            Ok(resp) => signals.whitelist_build_done(root_hex, resp.commitment_count),
            Err(e) => signals.whitelist_build_failed(format!("Failed to publish whitelist: {}", e)),
        }
    });
}

/// Shown whenever an admin action runs without a key loaded — which is the
/// normal state after a page reload, now that the key is never persisted.
const ADMIN_KEY_MISSING: &str =
    "Enter the relayer admin API key first. It is kept in memory for this page only and is \
     never written to browser storage, so it has to be re-entered after a reload.";

/// Compose the message shown when a snapshot is refused for want of
/// approvals.
///
/// Pure so the wording is unit-testable without a relayer. Falls back to the
/// relayer's own text when the pending count isn't known, rather than
/// asserting a number it can't back up.
fn nothing_approved_message(pending: Option<usize>, detail: &str) -> String {
    match pending {
        Some(n) if n > 0 => format!(
            "None of the {n} pending registration(s) have been approved yet. Review the list \
             above and approve the ones you recognise, then build the whitelist. (Relayer: {detail})"
        ),
        _ => format!(
            "The relayer has no approved registrations to snapshot. Refresh the pending list, \
             review it, and approve before building the whitelist. (Relayer: {detail})"
        ),
    }
}

/// Refresh the admin panel's pending registration list (and its count).
///
/// Fetches the commitments themselves, not just a number: the approval step
/// is only meaningful if the admin can see what they are approving.
pub fn refresh_pending_registrations(signals: AppSignals, admin_api_key: String) {
    signals.pending_registrations_error.set(None);
    if !crate::admin_key::is_usable(&admin_api_key) {
        signals
            .pending_registrations_error
            .set(Some(ADMIN_KEY_MISSING.to_string()));
        return;
    }
    let client = ApiClient::new(relayer_url());
    spawn_local(async move {
        match client.fetch_pending_registrations(&admin_api_key).await {
            Ok(commitments) => {
                signals.pending_registrations.set(Some(commitments.len()));
                signals.pending_commitments.set(Some(commitments));
            }
            Err(e) => signals.pending_registrations_error.set(Some(e.to_string())),
        }
    });
}

/// Approve the pending registrations currently on screen.
///
/// A **separate, deliberate step** from building the whitelist, and never
/// called from it. `POST /api/register` is public, so without a human saying
/// "I have reviewed this list" an attacker can flood the pending batch and a
/// blind snapshot would hand them the electorate.
///
/// Sends the exact commitments the admin is looking at rather than
/// `all: true`. That closes the window between the refresh and the click: a
/// registration that arrived in between is not swept in unreviewed, and if
/// the list has drifted the relayer reports the difference in `unknown`.
pub fn approve_pending_registrations(signals: AppSignals, admin_api_key: String) {
    submit_review(signals, admin_api_key, ReviewAction::Approve);
}

/// Reject (drop) the pending registrations currently on screen.
///
/// The other half of a usable review step: without it a Sybil batch stays
/// pending forever and every later review has to scroll past it.
pub fn reject_pending_registrations(signals: AppSignals, admin_api_key: String) {
    submit_review(signals, admin_api_key, ReviewAction::Reject);
}

/// Which review decision [`submit_review`] is applying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewAction {
    Approve,
    Reject,
}

impl ReviewAction {
    /// Past-tense verb for the result banner.
    fn past_tense(self) -> &'static str {
        match self {
            ReviewAction::Approve => "Approved",
            ReviewAction::Reject => "Rejected",
        }
    }
}

/// Shared body of approve/reject: same guards, same request, same reporting.
fn submit_review(signals: AppSignals, admin_api_key: String, action: ReviewAction) {
    signals.review_phase(crate::state::ReviewPhase::Submitting);

    if !crate::admin_key::is_usable(&admin_api_key) {
        signals.review_failed(ADMIN_KEY_MISSING);
        return;
    }

    // Only ever act on a list the admin has actually loaded. Approving
    // something never displayed is the rubber-stamp this gate exists to
    // prevent.
    let commitments = match signals.pending_commitments.get_untracked() {
        Some(c) if !c.is_empty() => c,
        Some(_) => {
            signals.review_failed(
                "There are no pending registrations to act on. Refresh the list first.",
            );
            return;
        }
        None => {
            signals.review_failed(
                "Load the pending registrations first so you can review them before deciding.",
            );
            return;
        }
    };

    let requested = commitments.len();
    let req = crate::api::ReviewRegistrationsRequest {
        commitments,
        all: false,
    };

    spawn_local(async move {
        let client = ApiClient::new(relayer_url());
        let result = match action {
            ReviewAction::Approve => client.approve_registrations(&admin_api_key, &req).await,
            ReviewAction::Reject => client.reject_registrations(&admin_api_key, &req).await,
        };

        match result {
            Ok(resp) => {
                signals.review_done(
                    review_summary(action, requested, &resp),
                    resp.affected,
                    resp.unknown.clone(),
                );
                signals.pending_registrations.set(Some(resp.total_pending));
                // The server-side batch moved under us; force a re-read
                // rather than leaving a list that no longer reflects it.
                signals.pending_commitments.set(None);
            }
            Err(e) => signals.review_failed(format!("Relayer error: {}", e)),
        }
    });
}

/// Build the human summary of a completed review.
///
/// Pure, so the arithmetic that tells an admin "2 of the 5 you sent were not
/// recognised" is testable without a relayer.
fn review_summary(
    action: ReviewAction,
    requested: usize,
    resp: &crate::api::ReviewRegistrationsResponse,
) -> String {
    let mut msg = format!(
        "{} {} of {} submitted registration(s). {} still pending.",
        action.past_tense(),
        resp.affected,
        requested,
        resp.total_pending
    );
    if !resp.unknown.is_empty() {
        // Never swallowed: an unrecognised entry means the list went stale
        // (or was mistyped), and silently applying the rest would hide that.
        msg.push_str(&format!(
            " {} were not recognised by the relayer - refresh the list and check before \
             building the whitelist.",
            resp.unknown.len()
        ));
    }
    msg
}

/// Generate the Groth16 proof via snarkjs.
async fn generate_proof(
    witness: crate::proofgen::VoteWitness,
) -> anyhow::Result<crate::proofgen::ProofResult> {
    let wasm_url = option_env!("VICHE_CIRCUIT_WASM_URL").unwrap_or("/circuits/vote.wasm");
    let zkey_url = option_env!("VICHE_CIRCUIT_ZKEY_URL").unwrap_or("/circuits/vote_final.zkey");

    let gen = crate::proofgen::ProofGenerator::new(wasm_url, zkey_url);
    gen.prove(&witness).await
}

// ---- WASM logging shim --------------------------------------------------

/// Log a warning to the browser console.
///
/// Note for anyone adding call sites: never pass a secret or the admin API
/// key through here. The console is readable by extensions and screen-shared
/// without a second thought.
fn tracing_warn(msg: String) {
    web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(&msg));
}

/// One-time startup cleanup: delete any relayer admin key an older build
/// persisted to web storage, and remember whether there was one.
///
/// Called from [`crate::app::App`]. See [`crate::admin_key`] for why the key
/// is no longer persisted at all, and why finding one means "rotate it", not
/// just "delete it".
pub fn purge_legacy_admin_api_key(signals: AppSignals) {
    if crate::admin_key::purge_persisted_admin_api_key() {
        signals.admin_key_was_persisted.set(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- validate_create_poll_input's *non-JS* branches (pure) -----------
    //
    // `validate_create_poll_input` reaches `onchain::parse_datetime_local_unix`
    // (a `js_sys::Date` call) once the merkle root and option count both
    // parse — that's not safe to invoke from a plain native `#[test]` (there
    // is no JS runtime to back the wasm-bindgen extern call), so those cases
    // live in the browser-run `wasm_tests` module below. Only the branches
    // that short-circuit *before* touching the date parser are exercised
    // here.

    #[test]
    fn validate_create_poll_input_rejects_bad_merkle_root() {
        let err = validate_create_poll_input("not-hex", "3", "2030-01-01T00:00").unwrap_err();
        assert!(err.contains("Invalid merkle root"));
    }

    #[test]
    fn validate_create_poll_input_rejects_too_few_options() {
        let root = format!("0x{}", "ab".repeat(32));
        let err = validate_create_poll_input(&root, "1", "2030-01-01T00:00").unwrap_err();
        assert!(err.contains("Number of options"));
        assert!(err.contains(">= 2"));
    }

    #[test]
    fn validate_create_poll_input_rejects_non_numeric_options() {
        let root = format!("0x{}", "ab".repeat(32));
        let err = validate_create_poll_input(&root, "three", "2030-01-01T00:00").unwrap_err();
        assert!(err.contains("Number of options"));
    }

    // ---- registration review messaging (pure) -----------------------------

    #[test]
    fn nothing_approved_message_names_the_pending_count() {
        let msg = nothing_approved_message(Some(7), "no approved registrations");
        assert!(msg.contains('7'), "count missing: {msg}");
        assert!(msg.contains("approve"), "no call to action: {msg}");
        // The relayer's own words are kept for diagnosis, not discarded.
        assert!(msg.contains("no approved registrations"), "detail lost: {msg}");
    }

    #[test]
    fn nothing_approved_message_falls_back_without_a_known_count() {
        // Must not assert a number it cannot back up.
        for pending in [None, Some(0)] {
            let msg = nothing_approved_message(pending, "nothing approved");
            assert!(msg.contains("Refresh"), "no recovery path: {msg}");
            assert!(!msg.contains(" 0 pending"), "claimed a bogus count: {msg}");
        }
    }

    #[test]
    fn review_summary_reports_affected_and_total() {
        let resp = crate::api::ReviewRegistrationsResponse {
            affected: 3,
            unknown: vec![],
            total_pending: 2,
        };
        let msg = review_summary(ReviewAction::Approve, 3, &resp);
        assert!(msg.starts_with("Approved 3 of 3"), "unexpected: {msg}");
        assert!(msg.contains("2 still pending"), "unexpected: {msg}");
        assert!(!msg.contains("not recognised"), "spurious warning: {msg}");
    }

    #[test]
    fn review_summary_surfaces_unknown_commitments() {
        // The whole reason `unknown` exists: a partially-applied list must
        // be visible, never silently dropped.
        let resp = crate::api::ReviewRegistrationsResponse {
            affected: 1,
            unknown: vec![U256::from(9u64), U256::from(10u64)],
            total_pending: 4,
        };
        let msg = review_summary(ReviewAction::Approve, 3, &resp);
        assert!(msg.contains("Approved 1 of 3"), "unexpected: {msg}");
        assert!(msg.contains("2 were not recognised"), "unexpected: {msg}");
    }

    // ---- review guards ----------------------------------------------------
    //
    // These all return before `spawn_local`, so they run on the native
    // target and are actually executed by `cargo test` rather than waiting
    // on a browser.

    #[test]
    fn review_refuses_without_an_admin_key() {
        let signals = AppSignals::new();
        signals
            .pending_commitments
            .set(Some(vec![U256::from(1u64)]));

        approve_pending_registrations(signals.clone(), String::new());
        let r = signals.review.get_untracked();
        assert_eq!(r.phase, crate::state::ReviewPhase::Failed);
        assert!(r.message.unwrap().contains("admin API key"));
    }

    #[test]
    fn review_refuses_when_no_list_has_been_loaded() {
        // Approving a batch the admin never saw is the rubber-stamp the
        // approval gate exists to prevent.
        let signals = AppSignals::new();
        approve_pending_registrations(signals.clone(), "k3y".into());
        let r = signals.review.get_untracked();
        assert_eq!(r.phase, crate::state::ReviewPhase::Failed);
        assert!(r.message.unwrap().contains("Load the pending registrations"));
    }

    #[test]
    fn review_refuses_an_empty_batch() {
        let signals = AppSignals::new();
        signals.pending_commitments.set(Some(vec![]));
        reject_pending_registrations(signals.clone(), "k3y".into());
        let r = signals.review.get_untracked();
        assert_eq!(r.phase, crate::state::ReviewPhase::Failed);
        assert!(r.message.unwrap().contains("no pending registrations"));
    }

    #[test]
    fn review_summary_uses_the_right_verb_for_reject() {
        let resp = crate::api::ReviewRegistrationsResponse {
            affected: 2,
            unknown: vec![],
            total_pending: 0,
        };
        let msg = review_summary(ReviewAction::Reject, 2, &resp);
        assert!(msg.starts_with("Rejected 2 of 2"), "unexpected: {msg}");
    }

    // ---- validate_close_poll_input (pure) ---------------------------------

    #[test]
    fn validate_close_poll_input_accepts_a_numeric_id() {
        assert_eq!(validate_close_poll_input("42").unwrap(), 42);
        assert_eq!(validate_close_poll_input("  7  ").unwrap(), 7);
    }

    #[test]
    fn validate_close_poll_input_rejects_non_numeric_id() {
        assert!(validate_close_poll_input("abc").is_err());
        assert!(validate_close_poll_input("").is_err());
        assert!(validate_close_poll_input("-1").is_err());
    }
}

#[cfg(test)]
mod wasm_tests {
    use super::*;
    use crate::state::AdminTxPhase;
    use crate::test_support::*;
    use wasm_bindgen_test::*;

    // `run_in_browser` is declared once, crate-wide, in `test_support`.

    const CONTRACT: &str = "0xCONTRACT";

    // Built via `.repeat()`, not hand-typed hex literals, so the length is
    // unambiguous: 20 bytes == exactly 40 hex chars.
    fn owner() -> String {
        format!("0x{}", "1a".repeat(20))
    }
    fn not_owner() -> String {
        format!("0x{}", "2b".repeat(20))
    }

    fn owner_mock_body() -> String {
        format!(
            r#"if (method === "eth_call") {{
                 return Promise.resolve("0x000000000000000000000000{}");
               }}
               return Promise.reject(new Error("unexpected method: " + method));"#,
            "1a".repeat(20)
        )
    }

    // ---- validate_create_poll_input's JS-touching branches ----------------
    //
    // These reach `onchain::parse_datetime_local_unix` (`js_sys::Date`), so
    // they need a real (or headless) browser — see the native `tests`
    // module above for the branches that don't.

    #[wasm_bindgen_test]
    fn validate_create_poll_input_accepts_well_formed_fields() {
        let root = format!("0x{}", "ab".repeat(32));
        let (parsed_root, num_options, deadline) =
            validate_create_poll_input(&root, "3", "2030-01-01T00:00").unwrap();
        assert_eq!(parsed_root, FixedBytes::<32>::from([0xabu8; 32]));
        assert_eq!(num_options, 3);
        assert!(deadline > 1_893_000_000, "deadline should be ~2030: {}", deadline);
    }

    #[wasm_bindgen_test]
    fn validate_create_poll_input_rejects_empty_deadline() {
        let root = format!("0x{}", "ab".repeat(32));
        let err = validate_create_poll_input(&root, "2", "").unwrap_err();
        assert!(err.contains("deadline"));
    }

    #[wasm_bindgen_test]
    fn validate_create_poll_input_rejects_garbage_deadline() {
        let root = format!("0x{}", "ab".repeat(32));
        let err = validate_create_poll_input(&root, "2", "not-a-date").unwrap_err();
        assert!(err.contains("deadline"));
    }

    // ---- is_owner --------------------------------------------------------

    #[wasm_bindgen_test]
    async fn is_owner_true_when_addresses_match_case_insensitively() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(&owner_mock_body(), true);
        let wallet = crate::wallet::detect().unwrap();
        assert!(is_owner(&wallet, CONTRACT, &owner().to_uppercase()).await);
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn is_owner_false_when_addresses_differ() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(&owner_mock_body(), true);
        let wallet = crate::wallet::detect().unwrap();
        assert!(!is_owner(&wallet, CONTRACT, &not_owner()).await);
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn is_owner_false_when_eth_call_fails() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(r#"return Promise.reject(new Error("rpc down"));"#, true);
        let wallet = crate::wallet::detect().unwrap();
        assert!(!is_owner(&wallet, CONTRACT, &owner()).await);
        remove_mock_ethereum();
    }

    // ---- check_admin -------------------------------------------------------

    #[wasm_bindgen_test]
    async fn check_admin_sets_true_for_the_owner_wallet() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(&owner_mock_body(), true);
        set_global_string("__VICHE_VOTING_MANAGER_ADDRESS__", CONTRACT);

        let signals = AppSignals::new();
        signals.wallet_connected(owner(), "0x1".to_string());
        check_admin(signals.clone());

        let settled = wait_until(|| signals.is_admin.get_untracked(), 50).await;
        assert!(settled, "is_admin never became true");

        remove_mock_ethereum();
        remove_global("__VICHE_VOTING_MANAGER_ADDRESS__");
    }

    #[wasm_bindgen_test]
    async fn check_admin_sets_false_for_a_non_owner_wallet() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(&owner_mock_body(), true);
        set_global_string("__VICHE_VOTING_MANAGER_ADDRESS__", CONTRACT);

        let signals = AppSignals::new();
        signals.wallet_connected(not_owner(), "0x1".to_string());
        signals.is_admin.set(true); // start "true" to prove it flips to false
        check_admin(signals.clone());

        wait_until(|| !signals.is_admin.get_untracked(), 50).await;
        assert!(!signals.is_admin.get_untracked());

        remove_mock_ethereum();
        remove_global("__VICHE_VOTING_MANAGER_ADDRESS__");
    }

    #[wasm_bindgen_test]
    fn check_admin_sets_false_synchronously_without_a_connected_wallet() {
        let signals = AppSignals::new();
        signals.is_admin.set(true);
        check_admin(signals.clone());
        // No wallet address means check_admin returns before spawning
        // anything, so this must already be false with no wait.
        assert!(!signals.is_admin.get_untracked());
    }

    #[wasm_bindgen_test]
    async fn check_admin_sets_false_synchronously_without_a_configured_contract() {
        let _guard = lock_global_mocks().await;
        remove_global("__VICHE_VOTING_MANAGER_ADDRESS__");
        let signals = AppSignals::new();
        signals.wallet_connected(owner(), "0x1".to_string());
        signals.is_admin.set(true);
        check_admin(signals.clone());
        assert!(!signals.is_admin.get_untracked());
    }

    // ---- submit_create_poll / submit_close_poll: fail-fast paths ---------

    #[wasm_bindgen_test]
    fn submit_create_poll_fails_synchronously_without_a_wallet() {
        let signals = AppSignals::new();
        submit_create_poll(
            signals.clone(),
            format!("0x{}", "ab".repeat(32)),
            "3".into(),
            "2030-01-01T00:00".into(),
            "ipfs://x".into(),
        );
        let s = signals.admin_create.get_untracked();
        assert_eq!(s.phase, AdminTxPhase::Failed);
        assert_eq!(s.message.as_deref(), Some("Connect your wallet first."));
    }

    #[wasm_bindgen_test]
    async fn submit_create_poll_fails_synchronously_on_bad_merkle_root() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(r#"return Promise.resolve("0x");"#, true);
        set_global_string("__VICHE_VOTING_MANAGER_ADDRESS__", CONTRACT);
        let signals = AppSignals::new();
        signals.wallet_connected(owner(), "0x1".to_string());

        submit_create_poll(
            signals.clone(),
            "not-hex".into(),
            "3".into(),
            "2030-01-01T00:00".into(),
            "ipfs://x".into(),
        );
        let s = signals.admin_create.get_untracked();
        assert_eq!(s.phase, AdminTxPhase::Failed);
        assert!(s.message.unwrap().contains("Invalid merkle root"));

        remove_mock_ethereum();
        remove_global("__VICHE_VOTING_MANAGER_ADDRESS__");
    }

    #[wasm_bindgen_test]
    async fn submit_close_poll_fails_synchronously_on_bad_poll_id() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(r#"return Promise.resolve("0x");"#, true);
        set_global_string("__VICHE_VOTING_MANAGER_ADDRESS__", CONTRACT);
        let signals = AppSignals::new();
        signals.wallet_connected(owner(), "0x1".to_string());

        submit_close_poll(signals.clone(), "not-a-number".into());
        let s = signals.admin_close.get_untracked();
        assert_eq!(s.phase, AdminTxPhase::Failed);
        assert_eq!(s.message.as_deref(), Some("Invalid poll id."));

        remove_mock_ethereum();
        remove_global("__VICHE_VOTING_MANAGER_ADDRESS__");
    }

    // ---- submit_create_poll / submit_close_poll: happy path --------------

    #[wasm_bindgen_test]
    async fn submit_create_poll_broadcasts_and_reports_the_tx_hash() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(
            r#"if (method === "eth_sendTransaction") { return Promise.resolve("0xTXHASH"); }
               return Promise.reject(new Error("unexpected method: " + method));"#,
            true,
        );
        set_global_string("__VICHE_VOTING_MANAGER_ADDRESS__", CONTRACT);
        let signals = AppSignals::new();
        signals.wallet_connected(owner(), "0x1".to_string());

        submit_create_poll(
            signals.clone(),
            format!("0x{}", "ab".repeat(32)),
            "3".into(),
            "2030-01-01T00:00".into(),
            "ipfs://x".into(),
        );

        let done = wait_until(
            || signals.admin_create.get_untracked().phase != AdminTxPhase::Submitting,
            50,
        )
        .await;
        assert!(done, "admin_create never left Submitting");
        let s = signals.admin_create.get_untracked();
        assert_eq!(s.phase, AdminTxPhase::Done);
        assert_eq!(s.tx_hash.as_deref(), Some("0xTXHASH"));

        remove_mock_ethereum();
        remove_global("__VICHE_VOTING_MANAGER_ADDRESS__");
    }

    #[wasm_bindgen_test]
    async fn submit_create_poll_reports_wallet_rejection() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(
            r#"return Promise.reject(new Error("user denied transaction signature"));"#,
            true,
        );
        set_global_string("__VICHE_VOTING_MANAGER_ADDRESS__", CONTRACT);
        let signals = AppSignals::new();
        signals.wallet_connected(owner(), "0x1".to_string());

        submit_create_poll(
            signals.clone(),
            format!("0x{}", "ab".repeat(32)),
            "3".into(),
            "2030-01-01T00:00".into(),
            "ipfs://x".into(),
        );

        wait_until(
            || signals.admin_create.get_untracked().phase != AdminTxPhase::Submitting,
            50,
        )
        .await;
        let s = signals.admin_create.get_untracked();
        assert_eq!(s.phase, AdminTxPhase::Failed);
        assert!(s.message.unwrap().contains("Transaction failed"));

        remove_mock_ethereum();
        remove_global("__VICHE_VOTING_MANAGER_ADDRESS__");
    }

    #[wasm_bindgen_test]
    async fn submit_close_poll_broadcasts_and_reports_the_tx_hash() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(
            r#"if (method === "eth_sendTransaction") { return Promise.resolve("0xCLOSEHASH"); }
               return Promise.reject(new Error("unexpected method: " + method));"#,
            true,
        );
        set_global_string("__VICHE_VOTING_MANAGER_ADDRESS__", CONTRACT);
        let signals = AppSignals::new();
        signals.wallet_connected(owner(), "0x1".to_string());

        submit_close_poll(signals.clone(), "7".into());

        let done = wait_until(
            || signals.admin_close.get_untracked().phase != AdminTxPhase::Submitting,
            50,
        )
        .await;
        assert!(done, "admin_close never left Submitting");
        let s = signals.admin_close.get_untracked();
        assert_eq!(s.phase, AdminTxPhase::Done);
        assert_eq!(s.tx_hash.as_deref(), Some("0xCLOSEHASH"));

        remove_mock_ethereum();
        remove_global("__VICHE_VOTING_MANAGER_ADDRESS__");
    }

    // ---- refresh_polls / fetch_polls_on_mount -----------------------------

    #[wasm_bindgen_test]
    fn fetch_polls_on_mount_skips_fetch_when_already_loaded() {
        let signals = AppSignals::new();
        signals.polls.set(Some(vec![]));
        // No relayer is reachable in this test env; if this tried to fetch
        // it would eventually set polls_error, not touch `polls` again. We
        // just assert the pre-loaded value is left completely alone.
        fetch_polls_on_mount(signals.clone());
        assert_eq!(signals.polls.get_untracked(), Some(vec![]));
    }

    // ---- voter secret actions ---------------------------------------------
    //
    // The derivation itself is covered in `crate::secret`; these cover the
    // signal plumbing, which is where a silent failure would hide.

    #[wasm_bindgen_test]
    fn load_secret_fails_fast_without_a_connected_wallet() {
        let signals = AppSignals::new();
        load_secret(signals.clone());
        let s = signals.secret.get_untracked();
        assert!(!s.busy, "must not sit spinning with no wallet to ask");
        assert_eq!(s.error.as_deref(), Some("Connect your wallet first."));
    }

    #[wasm_bindgen_test]
    async fn load_secret_publishes_a_derived_secret_into_the_signal() {
        let _guard = lock_global_mocks().await;
        let addr = "0xACTIONSECRET1";
        let _ = crate::secret::forget(addr);
        install_mock_ethereum(
            r#"if (method === "personal_sign") { return Promise.resolve("0x" + "4d".repeat(65)); }
               return Promise.reject(new Error("unexpected method: " + method));"#,
            true,
        );

        let signals = AppSignals::new();
        signals.wallet_connected(addr.to_string(), "0x1".to_string());
        load_secret(signals.clone());

        let settled = wait_until(|| signals.secret.get_untracked().value.is_some(), 50).await;
        assert!(settled, "secret never resolved");

        let s = signals.secret.get_untracked();
        assert!(!s.busy);
        assert!(s.error.is_none());
        assert_eq!(
            s.origin,
            Some(crate::secret::SecretOrigin::WalletDerivedV1)
        );
        assert_eq!(
            s.value,
            Some(
                crate::secret::derive_from_signature(&[0x4du8; 65])
                    .unwrap()
                    .to_string()
            )
        );

        remove_mock_ethereum();
        let _ = crate::secret::forget(addr);
    }

    #[wasm_bindgen_test]
    async fn load_secret_surfaces_a_refused_signature_as_an_error() {
        let _guard = lock_global_mocks().await;
        let addr = "0xACTIONSECRET2";
        let _ = crate::secret::forget(addr);
        install_mock_ethereum(
            r#"return Promise.reject(new Error("User rejected the request."));"#,
            true,
        );

        let signals = AppSignals::new();
        signals.wallet_connected(addr.to_string(), "0x1".to_string());
        load_secret(signals.clone());

        wait_until(|| signals.secret.get_untracked().error.is_some(), 50).await;
        let s = signals.secret.get_untracked();
        assert!(s.value.is_none(), "no secret should be invented on refusal");
        assert!(s.error.unwrap().contains("signature"));

        remove_mock_ethereum();
        let _ = crate::secret::forget(addr);
    }

    #[wasm_bindgen_test]
    fn import_secret_round_trips_a_backup_and_reports_it() {
        let addr = "0xACTIONIMPORT1";
        let _ = crate::secret::forget(addr);

        let signals = AppSignals::new();
        signals.wallet_connected(addr.to_string(), "0x1".to_string());
        import_secret(signals.clone(), "  90210  ".to_string());

        let s = signals.secret.get_untracked();
        assert_eq!(s.value.as_deref(), Some("90210"));
        assert_eq!(s.origin, Some(crate::secret::SecretOrigin::Imported));
        assert!(s.notice.is_some(), "the voter should be told it worked");
        assert!(s.error.is_none());

        let _ = crate::secret::forget(addr);
    }

    #[wasm_bindgen_test]
    fn import_secret_warns_when_the_backup_belongs_to_another_account() {
        let addr = "0xACTIONIMPORT2";
        let _ = crate::secret::forget(addr);

        let signals = AppSignals::new();
        signals.wallet_connected(addr.to_string(), "0x1".to_string());
        import_secret(
            signals.clone(),
            r#"{"viche_backup":1,"address":"0xSOMEONEELSE1234","secret":"777"}"#.to_string(),
        );

        let notice = signals.secret.get_untracked().notice.unwrap();
        assert!(notice.contains("not the connected account"), "no warning: {notice}");

        let _ = crate::secret::forget(addr);
    }

    #[wasm_bindgen_test]
    fn import_secret_rejects_garbage_without_touching_the_cache() {
        let addr = "0xACTIONIMPORT3";
        let _ = crate::secret::forget(addr);

        let signals = AppSignals::new();
        signals.wallet_connected(addr.to_string(), "0x1".to_string());
        import_secret(signals.clone(), "definitely not a secret".to_string());

        let s = signals.secret.get_untracked();
        assert!(s.error.is_some());
        assert!(s.value.is_none());
        assert!(crate::secret::cached(addr).unwrap().is_none());
    }

    #[wasm_bindgen_test]
    fn forget_secret_clears_the_cache_and_the_signal() {
        let addr = "0xACTIONFORGET1";
        let signals = AppSignals::new();
        signals.wallet_connected(addr.to_string(), "0x1".to_string());
        import_secret(signals.clone(), "12345".to_string());
        assert!(signals.secret.get_untracked().value.is_some());

        forget_secret(signals.clone());
        let s = signals.secret.get_untracked();
        assert!(s.value.is_none());
        assert!(s.origin.is_none());
        assert!(s.notice.is_some());
        assert!(crate::secret::cached(addr).unwrap().is_none());
    }

    // ---- relayer admin API key --------------------------------------------

    #[wasm_bindgen_test]
    fn admin_api_key_is_never_written_to_web_storage() {
        // The regression this whole change exists to prevent.
        let signals = AppSignals::new();
        signals.set_admin_api_key("top-secret-admin-key");
        assert_eq!(signals.admin_api_key_value(), "top-secret-admin-key");

        let window = web_sys::window().unwrap();
        for storage in [
            window.local_storage().unwrap().unwrap(),
            window.session_storage().unwrap().unwrap(),
        ] {
            let len = storage.length().unwrap();
            for i in 0..len {
                let key = storage.key(i).unwrap().unwrap_or_default();
                let value = storage.get_item(&key).unwrap().unwrap_or_default();
                assert!(
                    !value.contains("top-secret-admin-key"),
                    "admin key leaked into storage under {key}"
                );
            }
        }
    }

    #[wasm_bindgen_test]
    fn blank_admin_key_input_clears_rather_than_stores_an_empty_string() {
        let signals = AppSignals::new();
        signals.set_admin_api_key("abc");
        assert!(signals.admin_api_key.get_untracked().is_some());

        signals.set_admin_api_key("   ");
        assert!(signals.admin_api_key.get_untracked().is_none());
    }

    #[wasm_bindgen_test]
    fn clear_admin_api_key_forgets_it_immediately() {
        let signals = AppSignals::new();
        signals.set_admin_api_key("abc");
        signals.clear_admin_api_key();
        assert_eq!(signals.admin_api_key_value(), "");
    }

    #[wasm_bindgen_test]
    fn admin_actions_fail_fast_without_a_key_instead_of_sending_an_empty_bearer() {
        let signals = AppSignals::new();

        build_whitelist_from_registrations(signals.clone(), String::new());
        let build = signals.whitelist_build.get_untracked();
        assert_eq!(build.phase, WhitelistBuildPhase::Failed);
        assert!(build.message.unwrap().contains("admin API key"));

        refresh_pending_registrations(signals.clone(), "   ".to_string());
        assert!(signals
            .pending_registrations_error
            .get_untracked()
            .unwrap()
            .contains("admin API key"));
    }

    // ---- registration review ----------------------------------------------

    #[wasm_bindgen_test]
    async fn building_the_whitelist_never_performs_a_review() {
        // Guard against the tempting "fix" for the snapshot failure:
        // auto-approving inside the build flow would silently disable the
        // review gate while looking like a bug fix. If anyone ever wires an
        // approve call into `build_whitelist_from_registrations`, the review
        // signal moves off Idle and this fails.
        //
        // Browser-only: the build flow reaches `web_sys::window()` through
        // `ready_poseidon`, which cannot run on the native target.
        let signals = AppSignals::new();
        signals
            .pending_commitments
            .set(Some(vec![U256::from(1u64)]));

        build_whitelist_from_registrations(signals.clone(), "k3y".into());
        // Let the spawned task run as far as it can (it will fail at the
        // Poseidon bridge or the relayer call - either way, no review).
        next_tick().await;
        next_tick().await;

        assert_eq!(
            signals.review.get_untracked().phase,
            crate::state::ReviewPhase::Idle,
            "building a whitelist must never perform a review"
        );
    }

    #[wasm_bindgen_test]
    fn approving_sends_the_exact_list_the_admin_reviewed() {
        // The list is captured synchronously from `pending_commitments`, so
        // a registration arriving after the refresh cannot be swept in. This
        // asserts the batch is read before any await point.
        let signals = AppSignals::new();
        let batch = vec![U256::from(11u64), U256::from(22u64)];
        signals.pending_commitments.set(Some(batch.clone()));

        approve_pending_registrations(signals.clone(), "k3y".into());

        // It got past every guard and is in flight, meaning it accepted the
        // loaded batch rather than rejecting it.
        assert_eq!(
            signals.review.get_untracked().phase,
            crate::state::ReviewPhase::Submitting
        );
        // The snapshot of the batch happened before the request was spawned.
        assert_eq!(signals.pending_commitments.get_untracked(), Some(batch));
    }

    #[wasm_bindgen_test]
    fn review_phase_transition_clears_a_previous_result() {
        let signals = AppSignals::new();
        signals.review_done("Approved 2 of 2.", 2, vec![U256::from(5u64)]);
        assert!(signals.review.get_untracked().affected.is_some());

        signals.review_phase(crate::state::ReviewPhase::Submitting);
        let r = signals.review.get_untracked();
        assert!(r.affected.is_none(), "stale count survived");
        assert!(r.unknown.is_empty(), "stale unknown list survived");
        assert!(r.message.is_none());
    }

    #[wasm_bindgen_test]
    fn purge_legacy_admin_api_key_flags_a_previously_persisted_key() {
        let window = web_sys::window().unwrap();
        let storage = window.local_storage().unwrap().unwrap();
        storage
            .set_item(crate::admin_key::LEGACY_ADMIN_KEY_STORAGE_KEY, "old-key")
            .unwrap();

        let signals = AppSignals::new();
        purge_legacy_admin_api_key(signals.clone());

        assert!(
            signals.admin_key_was_persisted.get_untracked(),
            "the admin should be told to rotate the key"
        );
        assert_eq!(
            storage
                .get_item(crate::admin_key::LEGACY_ADMIN_KEY_STORAGE_KEY)
                .unwrap(),
            None
        );
    }
}
