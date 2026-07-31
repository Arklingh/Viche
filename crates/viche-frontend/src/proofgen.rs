//! Groth16 proof generation via snarkjs (in-page, in the browser).
//!
//! The witness is built in Rust from the voter's secret + Merkle path; the
//! actual proving is delegated to snarkjs's WASM prover, which loads the
//! circuit's `.wasm` (witness generator) and `.zkey` (proving key).
//!
//! ## Why generate proofs in the browser?
//!
//! The voter's `secret` is the only thing linking a ballot to an identity. If
//! the prover ran on a server, that server would learn the secret and
//! anonymity would collapse to "trust the operator". So we prove client-side.
//! Only `{proof, nullifier, voteOption}` leave the browser.
//!
//! ## Asset loading
//!
//! The circuit artifacts (`vote.wasm`, `vote_final.zkey`) are produced by
//! `make circuits` and must be served as static assets. In dev they live under
//! `/circuits/` (Trunk's `public_dir` or a `[[hooks]]` copy step); in
//! production they're served from a CDN/object store.
//!
//! ## Output format
//!
//! snarkjs returns `{ pi_a, pi_b, pi_c, protocol, curve }`. We repack it into
//! the 256-byte `abi.encode(pA, pB, pC)` blob that `VotingManager.castVote`
//! expects — exactly matching [`viche_core::wire::PROOF_BYTES`].

use alloy_primitives::{Bytes, U256};
use anyhow::{anyhow, Result};
use js_sys::{Array, Function, Promise};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::js_helpers::js_bigint_to_u256;

/// Result of a successful proof generation.
#[derive(Debug, Clone)]
pub struct ProofResult {
    /// The 256-byte `abi.encode(pA, pB, pC)` blob ready for `castVote`.
    pub proof_bytes: Bytes,
    /// The nullifier hash (`Poseidon(secret, voteId)`), one of the public signals.
    pub nullifier_hash: U256,
}

/// A Groth16 prover bound to specific circuit artifact URLs.
#[derive(Clone)]
pub struct ProofGenerator {
    /// URL to the circuit's witness-generator WASM (`vote_js/vote.wasm`).
    circuit_wasm_url: String,
    /// URL to the proving key (`vote_final.zkey`).
    zkey_url: String,
}

/// The witness input to the `vote` circuit, matching `vote.circom`.
///
/// Field names and order are dictated by the circuit's signal declarations.
/// circom reads big numbers as decimal strings; we build a plain JS object
/// of string-valued keys.
pub struct VoteWitness {
    /// The voter's secret (identity trapdoor).
    pub secret: U256,
    /// Sibling hashes from leaf to root (length = tree depth).
    pub path_elements: Vec<U256>,
    /// Direction at each level: `false` = LEFT, `true` = RIGHT.
    pub path_indices: Vec<bool>,
    /// The on-chain poll id (== `voteId` in the circuit).
    pub vote_id: U256,
    /// The Merkle root (public input; pinned from on-chain poll state).
    pub merkle_root: U256,
    /// The nullifier `Poseidon(secret, vote_id)` (public input).
    pub nullifier_hash: U256,
}

impl ProofGenerator {
    /// Create a prover pointing at the given circuit artifacts.
    pub fn new(circuit_wasm_url: impl Into<String>, zkey_url: impl Into<String>) -> Self {
        Self {
            circuit_wasm_url: circuit_wasm_url.into(),
            zkey_url: zkey_url.into(),
        }
    }

    /// Generate a Groth16 proof for the given witness.
    ///
    /// This is the heaviest operation in the app (~1-3s in a modern browser).
    /// It should be run off the main render thread or behind a loading state.
    pub async fn prove(&self, witness: &VoteWitness) -> Result<ProofResult> {
        let snarkjs_groth16 = snarkjs_groth16()
            .ok_or_else(|| anyhow!("snarkjs not loaded (window.snarkjs.groth16 missing)"))?;

        let input = build_witness_object(witness)?;

        // Call groth16.fullProve(input, wasmUrl, zkeyUrl) via JS interop.
        let full_prove_fn =
            js_sys::Reflect::get(&snarkjs_groth16, &"fullProve".into()).map_err(js_err)?;
        let full_prove: Function = full_prove_fn
            .dyn_into()
            .map_err(|_| anyhow!("snarkjs.groth16.fullProve is not a function"))?;

        let wasm_url_str = get_cached_asset_url(&self.circuit_wasm_url).await;
        let zkey_url_str = get_cached_asset_url(&self.zkey_url).await;

        let wasm_url = wasm_bindgen::JsValue::from_str(&wasm_url_str);
        let zkey_url = wasm_bindgen::JsValue::from_str(&zkey_url_str);
        let promise_value = full_prove
            .call3(&snarkjs_groth16, &input, &wasm_url, &zkey_url)
            .map_err(js_err)?;
        let promise: Promise = promise_value
            .dyn_into()
            .map_err(|_| anyhow!("snarkjs.groth16.fullProve did not return a Promise"))?;

        let resolved = JsFuture::from(promise)
            .await
            .map_err(|e| anyhow!("fullProve rejected: {:?}", e))?;

        // resolved = { publicSignals: [...], proof: { pi_a, pi_b, pi_c, ... } }
        let public_signals =
            js_sys::Reflect::get(&resolved, &"publicSignals".into()).map_err(js_err)?;
        let proof = js_sys::Reflect::get(&resolved, &"proof".into()).map_err(js_err)?;

        let proof_bytes = pack_proof_bytes(&proof)?;
        let nullifier_hash = extract_nullifier(&public_signals)?;

        Ok(ProofResult {
            proof_bytes,
            nullifier_hash,
        })
    }
}

/// Read `window.snarkjs.groth16` (or `window.snarkjs` and drill into `.groth16`).
fn snarkjs_groth16() -> Option<wasm_bindgen::JsValue> {
    let global = js_sys::global();
    let snarkjs = js_sys::Reflect::get(&global, &"snarkjs".into()).ok()?;
    if snarkjs.is_undefined() || snarkjs.is_null() {
        return None;
    }
    let groth16 = js_sys::Reflect::get(&snarkjs, &"groth16".into()).ok()?;
    if groth16.is_undefined() || groth16.is_null() {
        return None;
    }
    Some(groth16)
}

/// Resolve asset URL through the Cache Storage API helper `window.__VICHE_GET_CACHED_ASSET`
/// if present; fall back to the original URL string.
async fn get_cached_asset_url(url: &str) -> String {
    let global = js_sys::global();
    if let Ok(func) = js_sys::Reflect::get(&global, &"__VICHE_GET_CACHED_ASSET".into()) {
        if let Ok(f) = func.dyn_into::<Function>() {
            let arg = wasm_bindgen::JsValue::from_str(url);
            if let Ok(promise_val) = f.call1(&global, &arg) {
                if let Ok(promise) = promise_val.dyn_into::<Promise>() {
                    if let Ok(res) = JsFuture::from(promise).await {
                        if let Some(s) = res.as_string() {
                            return s;
                        }
                    }
                }
            }
        }
    }
    url.to_string()
}

/// Build the circom witness input object from a [`VoteWitness`].
///
/// circom expects all signals as decimal *strings* (it parses them as field
/// elements). Arrays become JS arrays of strings. `pathIndices` is `0`/`1`
/// per the circuit convention (`0` = LEFT child).
fn build_witness_object(witness: &VoteWitness) -> Result<wasm_bindgen::JsValue> {
    let obj = js_sys::Object::new();

    js_sys::Reflect::set(&obj, &"secret".into(), &witness.secret.to_string().into())
        .map_err(js_err)?;
    js_sys::Reflect::set(&obj, &"voteId".into(), &witness.vote_id.to_string().into())
        .map_err(js_err)?;
    js_sys::Reflect::set(
        &obj,
        &"merkleRoot".into(),
        &witness.merkle_root.to_string().into(),
    )
    .map_err(js_err)?;
    js_sys::Reflect::set(
        &obj,
        &"nullifierHash".into(),
        &witness.nullifier_hash.to_string().into(),
    )
    .map_err(js_err)?;

    let path_elements = Array::new();
    for e in &witness.path_elements {
        path_elements.push(&wasm_bindgen::JsValue::from_str(&e.to_string()));
    }
    js_sys::Reflect::set(&obj, &"pathElements".into(), &path_elements.into()).map_err(js_err)?;

    let path_indices_arr = Array::new();
    for b in &witness.path_indices {
        path_indices_arr.push(&wasm_bindgen::JsValue::from(if *b { 1u32 } else { 0u32 }));
    }
    js_sys::Reflect::set(&obj, &"pathIndices".into(), &path_indices_arr.into()).map_err(js_err)?;

    Ok(obj.into())
}

/// Pack `{ pi_a, pi_b, pi_c }` into the 256-byte
/// `abi.encode(uint256[2], uint256[2][2], uint256[2])` blob.
fn pack_proof_bytes(proof: &wasm_bindgen::JsValue) -> Result<Bytes> {
    let pi_a = js_sys::Reflect::get(proof, &"pi_a".into()).map_err(js_err)?;
    let pi_b = js_sys::Reflect::get(proof, &"pi_b".into()).map_err(js_err)?;
    let pi_c = js_sys::Reflect::get(proof, &"pi_c".into()).map_err(js_err)?;

    let pi_a: Array = pi_a
        .dyn_into()
        .map_err(|_| anyhow!("pi_a is not an array"))?;
    let pi_b: Array = pi_b
        .dyn_into()
        .map_err(|_| anyhow!("pi_b is not an array"))?;
    let pi_c: Array = pi_c
        .dyn_into()
        .map_err(|_| anyhow!("pi_c is not an array"))?;

    let a0 = parse_signal(&pi_a.get(0))?;
    let a1 = parse_signal(&pi_a.get(1))?;

    let b0 = pi_b
        .get(0)
        .dyn_into::<Array>()
        .map_err(|_| anyhow!("pi_b[0] not array"))?;
    let b1 = pi_b
        .get(1)
        .dyn_into::<Array>()
        .map_err(|_| anyhow!("pi_b[1] not array"))?;
    let b00 = parse_signal(&b0.get(0))?;
    let b01 = parse_signal(&b0.get(1))?;
    let b10 = parse_signal(&b1.get(0))?;
    let b11 = parse_signal(&b1.get(1))?;

    let c0 = parse_signal(&pi_c.get(0))?;
    let c1 = parse_signal(&pi_c.get(1))?;

    let mut bytes = Vec::with_capacity(256);
    push_u256(&mut bytes, &a0);
    push_u256(&mut bytes, &a1);
    // snarkjs proof JSON stores G2 coordinates in the opposite inner order
    // from the generated Solidity verifier's uint256[2][2] ABI argument.
    push_u256(&mut bytes, &b01);
    push_u256(&mut bytes, &b00);
    push_u256(&mut bytes, &b11);
    push_u256(&mut bytes, &b10);
    push_u256(&mut bytes, &c0);
    push_u256(&mut bytes, &c1);

    debug_assert_eq!(
        bytes.len(),
        viche_core::wire::PROOF_BYTES,
        "packed proof must be exactly PROOF_BYTES"
    );

    Ok(Bytes::from(bytes))
}

/// Extract the nullifier hash from the public signals.
fn extract_nullifier(public_signals: &wasm_bindgen::JsValue) -> Result<U256> {
    let arr: Array = public_signals
        .clone()
        .dyn_into()
        .map_err(|_| anyhow!("publicSignals is not an array"))?;
    if arr.length() < 3 {
        return Err(anyhow!("publicSignals has fewer than 3 elements"));
    }
    let nullifier = parse_signal(&arr.get(2))?;
    Ok(nullifier)
}

/// Parse a single circom signal (string or bigint) into a [`U256`].
fn parse_signal(v: &wasm_bindgen::JsValue) -> Result<U256> {
    js_bigint_to_u256(v).map_err(|e| anyhow!("signal parse failed: {:?}", e))
}

/// Append a U256 to a byte vector as 32 big-endian bytes.
fn push_u256(out: &mut Vec<u8>, v: &U256) {
    out.extend_from_slice(&v.to_be_bytes::<32>());
}

/// Turn a `JsValue` error into an `anyhow` error.
fn js_err(e: wasm_bindgen::JsValue) -> anyhow::Error {
    anyhow!("JS error: {:?}", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm_witness_serialization() {
        let witness = VoteWitness {
            secret: U256::from(42u64),
            path_elements: vec![U256::from(10u64)],
            path_indices: vec![false],
            vote_id: U256::from(1u64),
            merkle_root: U256::from(100u64),
            nullifier_hash: U256::from(200u64),
        };
        let js_obj = build_witness_object(&witness).unwrap();
        assert!(js_sys::Reflect::has(&js_obj, &"secret".into()).unwrap());
        assert!(js_sys::Reflect::has(&js_obj, &"voteId".into()).unwrap());
        assert!(js_sys::Reflect::has(&js_obj, &"merkleRoot".into()).unwrap());
        assert!(js_sys::Reflect::has(&js_obj, &"nullifierHash".into()).unwrap());
    }

    #[test]
    fn test_push_u256_endianness_and_length() {
        let mut out = Vec::new();
        let val = U256::from(0x12345678u64);
        push_u256(&mut out, &val);

        assert_eq!(out.len(), 32);
        // Big endian: lowest bytes are at the end
        assert_eq!(out[28..32], [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&out[0..28], &[0u8; 28]);
    }

    #[test]
    fn test_vote_witness_instantiation() {
        let witness = VoteWitness {
            secret: U256::from(100u64),
            path_elements: vec![U256::from(1u64), U256::from(2u64)],
            path_indices: vec![false, true],
            vote_id: U256::from(1u64),
            merkle_root: U256::from(999u64),
            nullifier_hash: U256::from(888u64),
        };

        assert_eq!(witness.secret, U256::from(100u64));
        assert_eq!(witness.path_elements.len(), 2);
        assert_eq!(witness.path_indices, vec![false, true]);
    }
}

