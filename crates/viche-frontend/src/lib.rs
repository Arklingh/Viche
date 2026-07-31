//! `viche-frontend` — Leptos WASM single-page UI for Viche.
//!
//! ## Architecture
//!
//! ```text
//!   ┌──────────────── browser ────────────────┐
//!   │  Leptos SPA (this crate)                │
//!   │    ├── connect injected EIP-1193 wallet │
//!   │    ├── fetch poll list from relayer     │
//!   │    ├── generate Groth16 proof in-page   │
//!   │    │   (snarkjs wasm + viche-core tree) │
//!   │    ├── POST {proof,nullifier,option}    │
//!   │    │   to viche-relayer                 │
//!   │    └── poll tx receipt, update tally    │
//!   └──────────────────────────────────────────┘
//! ```
//!
//! ## Why proof generation lives in the browser
//!
//! The voter's `secret` is the *only* thing linking a ballot to an identity.
//! If the relayer ever saw it, anonymity would collapse to "trust the relayer".
//! So the proof is computed client-side against the Merkle path the voter
//! derives from their `secret`; only `{proof, nullifier, voteOption}` leave
//! the browser. The relayer never learns `secret`.
//!
//! ## Module layout
//!
//! - [`app`] — root component + view routing.
//! - [`actions`] — async workflows (connect, fetch, vote).
//! - [`state`] — global reactive signals.
//! - [`api`] — relayer HTTP client (gloo-net).
//! - [`wallet`] — EIP-1193 bridge.
//! - [`crypto`] — circomlibjs Poseidon provider.
//! - [`proofgen`] — snarkjs proof generation.
//! - [`components`] — Leptos view components.
//! - [`config`] — runtime URL configuration.
//! - [`js_helpers`] — U256 ↔ JS bigint conversions.

#![forbid(unsafe_code)]

pub mod actions;
pub mod api;
pub mod app;
pub mod components;
pub mod config;
pub mod crypto;
pub mod js_helpers;
pub mod proofgen;
pub mod state;
pub mod wallet;

/// WASM entry point. Called by `trunk`/`wasm-bindgen` once the `.wasm` module
/// is instantiated.
///
/// We install the panic hook first so any Rust panic surfaces as a readable
/// stack trace in the browser console, then mount the root [`app::App`].
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn lib_main() {
    console_error_panic_hook::set_once();

    // Optional: log a boot marker.
    web_sys::console::log_1(&"Viche frontend booting…".into());

    leptos::mount_to_body(|| {
        use leptos::*;
        view! { <crate::app::App /> }
    });
}
