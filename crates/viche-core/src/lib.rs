//! `viche-core` — shared Viche primitives.
//!
//! This crate is the single source of truth for the cryptographic conventions
//! shared by the relayer (`viche-relayer`) and the browser frontend
//! (`viche-frontend`). Anything that produces or consumes a Viche ZK proof
//! depends on it, because all three must agree on:
//!
//!   * the BN254 scalar field modulus and the reduction helpers;
//!   * the Poseidon hash function (parameterised to match circomlib);
//!   * the sparse Merkle tree convention;
//!   * the wire format exchanged over HTTP between the browser and relayer.
//!
//! ## Why this matters
//!
//! The on-chain `Groth16Verifier` was generated from `vote.circom` and
//! therefore hardcodes a specific Poseidon parameterisation and Merkle
//! convention. If any implementation disagrees in *any* bit, proofs won't
//! verify and Merkle roots won't match the public inputs — the classic
//! "works in test vectors, fails on-chain" trap. The reference implementation
//! lives in `circuits/scripts/gen_input.js`; port it field-for-field.
//!
//! ## Module map
//!
//! - [`field`] — BN254 scalar field modulus, reduction, and validation.
//! - [`poseidon`] — `PoseidonProvider` trait (implemented by the browser via
//!   circomlibjs or natively in Rust).
//! - [`merkle`] — Sparse Poseidon Merkle tree, generic over the hasher.
//! - [`wire`] — Serde types for the relayer's HTTP API.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod field;
pub mod merkle;
pub mod poseidon;
pub mod wire;
