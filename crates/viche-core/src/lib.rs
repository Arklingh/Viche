//! `viche-core` — shared Viche primitives.
//!
//! This crate is the single source of truth for the cryptographic conventions
//! shared by the relayer (`viche-relayer`) and the browser frontend
//! (`viche-frontend`). Anything that produces or consumes a Viche ZK proof
//! depends on it, because all three must agree on:
//!
//!   * the BN254 scalar field modulus and the reduction helpers;
//!   * the Poseidon hash parameters (circomlib's BN254 set);
//!   * the sparse Poseidon Merkle tree layout and its zero-hash chain;
//!   * the wire format exchanged over HTTP between the browser and relayer.
//!
//! ## Why this matters
//!
//! The on-chain `Groth16Verifier` was generated from `vote.circom` and
//! therefore hardcodes a specific Poseidon parameterisation and Merkle
//! convention. If the Rust implementation here disagrees in *any* bit, proofs
//! won't verify and Merkle roots won't match the public inputs — the classic
//! "works in test vectors, fails on-chain" trap. The reference implementation
//! lives in `circuits/scripts/gen_input.js`; port it field-for-field.
//!
//! ## Status — Phase 1 scaffold
//!
//! This file is intentionally a stub. The Phase 2 work item is:
//!
//! 1. Implement `field` — BN254 modulus, modular reduction, from/to bytes.
//! 2. Implement `poseidon` — circomlib-equivalent parameters over BN254.
//! 3. Implement `merkle` — sparse incremental Poseidon tree with the
//!    zero-hash chain matching `circuits/circuits/merkle_tree.circom`.
//! 4. Implement `wire` — serde types for the relayer's `POST /api/vote`.
//!
//! Each module below lists its precise contract.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// BN254 scalar field arithmetic.
///
/// Contract:
///   * `MODULUS` = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
///   * `reduce(x)` returns `x mod MODULUS` for arbitrary-precision integers.
///   * `from_be_bytes` / `to_be_bytes` round-trip field elements.
///
/// Phase 2: choose a backing crate (likely `ark-bn254` + `ark-ff`, or
/// `halo2curves` for the WASM-friendly variant).
pub mod field {
    /// The BN254 scalar field modulus, as a decimal string for documentation.
    ///
    /// In Rust this is exposed as a `U256` (from `ruint` or similar) once
    /// Phase 2 picks a crate.
    pub const MODULUS_DEC: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";
}

/// Poseidon hash over BN254, parameterised to match circomlib.
///
/// Contract:
///   * `hash_1(x)`       == circomlib `Poseidon(1)(x)`
///   * `hash_2(x, y)`    == circomlib `Poseidon(2)(x, y)`
///   * Parameters: BN254 field, `t = 3` (for 2 inputs), `R_F = 8`, `R_P = 57`,
///     and the exact round constants / MDS matrix circomlib ships.
///
/// Phase 2 will likely wrap `poc-proof-systems`/`appliedzkp` Poseidon or
/// `arkworks-rs/algebra`'s gadget-friendly primitive.
pub mod poseidon {}

/// Sparse Poseidon Merkle tree.
///
/// Contract (must match `circuits/circuits/merkle_tree.circom`):
///   * `parent = Poseidon(left, right)`
///   * `zeros[0] = 0`, `zeros[i] = Poseidon(zeros[i-1], zeros[i-1])`
///   * `insert(leaf)` returns its leaf index.
///   * `proof(index)` returns `MerkleProof { pathElements, pathIndices }`
///     where `pathIndices[i] == 0` means our node is the LEFT child at level `i`.
///   * `root()` exposes the current root.
///
/// The default tree depth is 20 (see `circuits/circuits/vote.circom`).
pub mod merkle {}

/// Wire types for the relayer HTTP API.
///
/// Contract (Phase 2): serde-serialisable structs for
///   * `VoteRequest { poll_id, vote_option, nullifier_hash, proof }`
///   * `VoteResponse { tx_hash, status }`
///
/// `proof` is the `abi.encode(pA, pB, pC)` blob the contract decodes.
pub mod wire {}
