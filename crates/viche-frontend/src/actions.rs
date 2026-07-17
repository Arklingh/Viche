//! Async orchestration: wallet connect, poll fetches, and the vote pipeline.
//!
//! Each action spawns a `wasm-bindgen-futures` task that drives the relevant
//! module and writes results back into the shared [`AppSignals`]. Components
//! stay declarative — they call these actions in event handlers and read the
//! resulting signal updates.

use alloy_primitives::{Bytes, U256};
use leptos::{spawn_local, SignalGet, SignalSet, SignalUpdate, SignalGetUntracked};
use viche_core::wire::{NullifierHash, Proof, VoteRequest};

use crate::api::ApiClient;
use crate::config::relayer_url;
use crate::state::{AppSignals, VotePhase};

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
            (Some(addr), Some(cid)) => signals.wallet_connected(addr, cid),
            (Some(addr), None) => signals.wallet_connected(addr, String::new()),
            _ => signals.wallet_error("Wallet returned no accounts."),
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
        // 1. Resolve the voter's secret (per-account, in localStorage).
        let wallet_addr: String = match signals.wallet.get_untracked().address.clone() {
            Some(a) => a,
            None => {
                signals.vote_failed("Connect your wallet first.");
                return;
            }
        };
        let secret = match load_or_create_secret(&wallet_addr) {
            Ok(s) => s,
            Err(e) => {
                signals.vote_failed(format!("Failed to load secret: {}", e));
                return;
            }
        };
        signals.secret.set(Some(secret.to_string()));

        // 2. Build the Merkle witness.
        let witness = match build_witness(&secret, &poll_id, &merkle_root) {
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

// ---- helpers ------------------------------------------------------------

/// Load the voter's secret from localStorage, keyed by their address. If none
/// exists, generate one and persist it.
fn load_or_create_secret(address: &str) -> anyhow::Result<U256> {
    let key = format!("viche:secret:{}", address);

    if let Some(stored) = local_storage_get(&key) {
        if let Ok(v) = U256::from_str_radix(stored.trim(), 10) {
            return Ok(v);
        }
    }

    // Generate a fresh random field element via Web Crypto (through getrandom).
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| anyhow::anyhow!("rng failed: {}", e))?;
    let raw = U256::from_be_bytes(buf);
    let secret = viche_core::field::reduce(&raw);
    let _ = local_storage_set(&key, &secret.to_string());
    Ok(secret)
}

/// Build the Merkle witness for the voter's secret.
///
/// viche v1 ships with the demo whitelist from `gen_input.js` (three fixed
/// voters). A production deployment would expose an admin endpoint returning
/// the membership proof for a given commitment.
fn build_witness(
    secret: &U256,
    poll_id: &str,
    merkle_root: &str,
) -> anyhow::Result<crate::proofgen::VoteWitness> {
    use viche_core::merkle::{SparseMerkleTree, DEFAULT_DEPTH};
    use viche_core::poseidon::PoseidonProvider;

    let window = web_sys::window()
        .ok_or_else(|| anyhow::anyhow!("No browser window context found"))?;
    
    let js_val = js_sys::Reflect::get(&window, &"__VICHE_CRYPTO_READY__".into())
        .map_err(|_| anyhow::anyhow!("Failed to search window variables"))?;

    // Verify the flag is set and evaluates to true
    if js_val.is_undefined() || js_val.is_null() || !js_val.as_bool().unwrap_or(false) {
        return Err(anyhow::anyhow!(
            "Web3 Cryptographic engine is loading. Please wait 3 seconds and click vote again."
        ));
    }
    
    let poseidon = crate::crypto::CircomlibPoseidon::new()
        .map_err(|e| anyhow::anyhow!("Crypto engine not ready: {:?}", e))?;

    // The demo whitelist secrets — must match gen_input.js exactly.
    let demo_voters: [U256; 3] = [
        U256::from_str_radix("12345678901234567890", 10).unwrap(),
        U256::from_str_radix("98765432109876543210", 10).unwrap(),
        U256::from_str_radix("55555555555555555555", 10).unwrap(),
    ];

    let mut tree: SparseMerkleTree<crate::crypto::CircomlibPoseidon, DEFAULT_DEPTH> =
        SparseMerkleTree::new(&poseidon);

    let mut voter_index: Option<u64> = None;
    for v in &demo_voters {
        let commitment = poseidon.hash_1(v)?;
        let idx = tree.insert(&poseidon, commitment);
        if v == secret {
            voter_index = Some(idx);
        }
    }

    let idx = voter_index.ok_or_else(|| {
        anyhow::anyhow!(
            "Voter secret not in the demo whitelist. viche v1 supports only the three demo voters."
        )
    })?;

    let proof = tree.proof(idx);

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

/// Generate the Groth16 proof via snarkjs.
async fn generate_proof(
    witness: crate::proofgen::VoteWitness,
) -> anyhow::Result<crate::proofgen::ProofResult> {
    let wasm_url = option_env!("VICHE_CIRCUIT_WASM_URL").unwrap_or("/circuits/vote.wasm");
    let zkey_url = option_env!("VICHE_CIRCUIT_ZKEY_URL").unwrap_or("/circuits/vote_final.zkey");

    let gen = crate::proofgen::ProofGenerator::new(wasm_url, zkey_url);
    gen.prove(&witness).await
}

// ---- WASM storage + logging shims --------------------------------------

/// `localStorage.getItem(key)`.
fn local_storage_get(key: &str) -> Option<String> {
    let win = web_sys::window()?;
    let storage = win.local_storage().ok()??;
    storage.get_item(key).ok().flatten()
}

/// `localStorage.setItem(key, value)`.
fn local_storage_set(key: &str, value: &str) -> Option<()> {
    let win = web_sys::window()?;
    let storage = win.local_storage().ok()??;
    storage.set_item(key, value).ok()?;
    Some(())
}

/// Log a warning to the browser console.
fn tracing_warn(msg: String) {
    web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(&msg));
}
