//! Poseidon hash trait for Viche.
//!
//! The Viche circuit uses two Poseidon configurations from circomlib:
//!
//!   * `Poseidon(1)` — one input, for identity commitments: `leaf = H(secret)`
//!   * `Poseidon(2)` — two inputs, for Merkle parents, nullifiers, etc.
//!
//! Both operate over the BN254 scalar field (`p ≈ 2^254`), parameterised with
//! `t = 3` (width), `R_F = 8` full rounds, `R_P = 57` partial rounds.
//!
//! ## Why a trait?
//!
//! The only consumers that actually *hash* are the browser frontend and native
//! tests. The relayer never hashes anything — it forwards pre-built proofs.
//! The browser must match circomlib exactly, so it calls `circomlibjs` via
//! `wasm-bindgen`. A native Rust Poseidon implementation can be provided later
//! (e.g. for relayer-side pre-checks) without changing the Merkle tree code.
//!
//! All implementations of this trait **MUST** produce outputs identical to
//! circomlib's `Poseidon` function, or proofs will fail to verify on-chain.

use alloy_primitives::U256;
use thiserror::Error;

/// Error returned by Poseidon hash operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PoseidonError {
    /// The hash function is not initialised (e.g. WASM module not loaded).
    #[error("Poseidon provider not initialised")]
    NotReady,
    /// An input value is outside the BN254 scalar field.
    #[error("Poseidon input out of field: {0}")]
    OutOfField(U256),
    /// An opaque error from the underlying WASM bridge.
    #[error("Poseidon bridge error: {0}")]
    Bridge(String),
}

/// Provider of Poseidon hash functions matching circomlib over BN254.
///
/// Implementations must produce outputs identical to:
///   * `circomlibjs.poseidon([x])`       for [`PoseidonProvider::hash_1`]
///   * `circomlibjs.poseidon([x, y])`   for [`PoseidonProvider::hash_2`]
///
/// Both inputs and outputs are BN254 scalar field elements (< `field::MODULUS`).
pub trait PoseidonProvider: Clone + Send + Sync {
    /// Compute `Poseidon(1)(x)`, the one-input Poseidon hash.
    ///
    /// Used for identity commitments: `leaf = H(secret)`.
    fn hash_1(&self, x: &U256) -> Result<U256, PoseidonError>;

    /// Compute `Poseidon(2)(x, y)`, the two-input Poseidon hash.
    ///
    /// Used for:
    ///   * Merkle parent: `H(left, right)`
    ///   * Nullifier: `H(secret, voteId)`
    fn hash_2(&self, x: &U256, y: &U256) -> Result<U256, PoseidonError>;
}
