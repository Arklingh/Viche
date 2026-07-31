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

fn global_string(key: &str) -> Option<String> {
    let value = js_sys::Reflect::get(&js_sys::global(), &key.into()).ok()?;
    if value.is_undefined() || value.is_null() {
        return None;
    }
    value.as_string()
}
