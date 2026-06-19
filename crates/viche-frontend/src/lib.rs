//! `viche-frontend` — Leptos WASM single-page UI for Viche.
//!
//! Phase 3 architecture:
//!
//! ```text
//!   ┌──────────────── browser ────────────────┐
//!   │  Leptos SPA (this crate)                │
//!   │    ├── connect injected EIP-1193 wallet │
//!   │    ├── fetch poll list from chain        │
//!   │    ├── generate Groth16 proof in-page    │
//!   │    │   (snarkjs wasm + viche-core tree)  │
//!   │    ├── POST {proof,nullifier,option}     │
//!   │    │   to viche-relayer                  │
//!   │    └── poll tx receipt, update tally     │
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
//! ## Phase 1 status
//!
//! This file is a stub so the workspace compiles. Phase 3 will introduce the
//! Leptos components, the `wasm-bindgen` bindings to `window.ethereum`, and
//! the snarkjs-wasm proof-generation glue.

#![forbid(unsafe_code)]
