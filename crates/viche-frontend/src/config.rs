//! Frontend runtime configuration.
//!
//! The browser bundle has no `.env` loader; configuration comes from build-time
//! constants (compiled into the WASM) and is overridable at runtime via URL
//! query params or `window` globals. For a small community dApp we keep it
//! simple: sensible defaults, one place to change them.

/// Default relayer base URL (the Trunk dev proxy forwards `/api/*` here).
///
/// In production, set this at build time:
///   VICHE_RELAYER_URL=https://relayer.example.com cargo build --release
pub const RELAYER_URL: &str = match option_env!("VICHE_RELAYER_URL") {
    Some(url) => url,
    None => "",
};

/// Resolve the relayer base URL at runtime.
///
/// Priority:
///   1. `window.__VICHE_RELAYER_URL__` (set by a `<script>` on the page),
///   2. the compile-time `VICHE_RELAYER_URL` env var,
///   3. empty string → the frontend talks same-origin (Trunk proxy or reverse
///      proxy in prod), so calls go to `/api/...` directly.
pub fn relayer_url() -> String {
    if let Some(url) = global_string("__VICHE_RELAYER_URL__") {
        let trimmed = url.trim().trim_end_matches('/').to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }

    let compiled = RELAYER_URL;
    if !compiled.is_empty() {
        return compiled.trim_end_matches('/').to_string();
    }

    // Otherwise fall back to same-origin (empty base). The Trunk dev proxy and
    // a production reverse proxy both expose /api at the same origin.
    String::new()
}

/// The default chain id the dApp expects (1 = Ethereum mainnet). Override via
/// `window.__VICHE_CHAIN_ID__` for testnet deployments.
pub fn expected_chain_id_hex() -> String {
    if let Some(chain_id) = global_string("__VICHE_CHAIN_ID__") {
        let trimmed = chain_id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    option_env!("VICHE_CHAIN_ID").unwrap_or("0x1").to_string()
}

/// The deployed `VotingManager` contract address, for admin transactions sent
/// directly from the connected wallet (createPoll/closePoll bypass the
/// relayer entirely — see [`crate::onchain`]).
///
/// Priority: `window.__VICHE_VOTING_MANAGER_ADDRESS__`, then the compile-time
/// `VICHE_VOTING_MANAGER_ADDRESS` env var. `None` if neither is set.
pub fn voting_manager_address() -> Option<String> {
    if let Some(addr) = global_string("__VICHE_VOTING_MANAGER_ADDRESS__") {
        let trimmed = addr.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }

    option_env!("VICHE_VOTING_MANAGER_ADDRESS")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn global_string(key: &str) -> Option<String> {
    let value = js_sys::Reflect::get(&js_sys::global(), &key.into()).ok()?;
    if value.is_undefined() || value.is_null() {
        return None;
    }
    value.as_string()
}
