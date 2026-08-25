//! Async orchestration: wallet connect, poll fetches, and the vote pipeline.
//!
//! Each action spawns a `wasm-bindgen-futures` task that drives the relevant
//! module and writes results back into the shared [`AppSignals`]. Components
//! stay declarative — they call these actions in event handlers and read the
//! resulting signal updates.

use alloy_primitives::{Bytes, FixedBytes, U256};
use leptos::{spawn_local, SignalGet, SignalSet, SignalUpdate, SignalGetUntracked};
use viche_core::wire::{NullifierHash, Proof, VoteRequest};

use crate::api::ApiClient;
use crate::config::relayer_url;
use crate::state::{AdminTxPhase, AppSignals, VotePhase};
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

    // ---- load_or_create_secret ---------------------------------------------

    #[wasm_bindgen_test]
    fn load_or_create_secret_persists_and_reuses_a_generated_secret() {
        let addr = "0xSECRETTEST1";
        let window = web_sys::window().unwrap();
        let storage = window.local_storage().unwrap().unwrap();
        let _ = storage.remove_item(&format!("viche:secret:{}", addr));

        let first = load_or_create_secret(addr).unwrap();
        let second = load_or_create_secret(addr).unwrap();
        assert_eq!(first, second, "second call should reuse the persisted secret");

        let _ = storage.remove_item(&format!("viche:secret:{}", addr));
    }

    #[wasm_bindgen_test]
    fn load_or_create_secret_regenerates_on_corrupt_storage() {
        let addr = "0xSECRETTEST2";
        let window = web_sys::window().unwrap();
        let storage = window.local_storage().unwrap().unwrap();
        let key = format!("viche:secret:{}", addr);
        storage.set_item(&key, "not-a-number").unwrap();

        // Should not error out — falls back to generating a fresh secret.
        let secret = load_or_create_secret(addr).unwrap();
        assert_ne!(secret, U256::ZERO);

        let _ = storage.remove_item(&key);
    }
}
