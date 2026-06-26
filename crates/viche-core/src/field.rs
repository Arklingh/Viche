//! BN254 scalar field arithmetic for Viche.
//!
//! Every signal that flows into the `vote.circom` circuit — `secret`, `voteId`
//! (= on-chain `pollId`), `merkleRoot`, `nullifierHash`, every Merkle hash — is
//! an element of the BN254 scalar field. The relayer does not need to *produce*
//! any of these (the proof comes pre-built from the browser), but it must
//! **reject** payloads whose public inputs lie outside the field before
//! forwarding them on-chain. Otherwise a malformed `pubSignals` array would
//! make the `castVote` call fail at the EVM level with an opaque revert,
//! wasting relayer gas on garbage.
//!
//! ## Field modulus
//!
//! ```text
//! p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//!   = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
//! ```
//!
//! The scalar field is 254 bits wide, so it fits losslessly in a [`U256`].
//!
//! ## What lives here vs. Phase 3
//!
//! Phase 2 only needs *validation* (`is_in_field`, `reduce`). Full hashing
//! primitives (`poseidon`) and the Merkle tree live in Phase 3, where they are
//! actually exercised by the browser prover.

use alloy_primitives::{uint, U256};
use thiserror::Error;

/// The BN254 scalar field modulus, as a [`U256`].
///
/// ```text
/// 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
/// ```
///
/// Constructed via the `uint!` macro so the literal is parsed at compile
/// time — hand-packing 64-bit limbs is a classic source of off-by-one bugs.
pub const MODULUS: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

/// Decimal form, for documentation / JSON where a hex prefix is undesirable.
pub const MODULUS_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Error returned when a value is not a valid field element.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FieldError {
    /// The value is `>= MODULUS` and the caller did not ask for a reduction.
    #[error("value {0} is not in the BN254 scalar field (>= modulus)")]
    OutOfRange(U256),
}

/// Returns `true` iff `x` is a valid field element, i.e. `x < MODULUS`.
///
/// # Example
///
/// ```
/// use viche_core::field::{MODULUS, is_in_field};
/// use alloy_primitives::U256;
///
/// assert!(is_in_field(&U256::ZERO));
/// assert!(is_in_field(&U256::from(7u64)));
/// assert!(!is_in_field(&MODULUS));          // modulus itself is out of range
/// let one_past = MODULUS + U256::from(1u64);
/// assert!(!is_in_field(&one_past));
/// ```
#[inline]
pub fn is_in_field(x: &U256) -> bool {
    *x < MODULUS
}

/// Reduce `x` modulo the BN254 scalar field, returning `x mod p`.
///
/// Useful when the frontend sends a raw `pollId` or `secret` that has not yet
/// been reduced; the circuit itself does this implicitly, but emitting the
/// reduced form keeps the wire payload canonical.
///
/// # Example
///
/// ```
/// use viche_core::field::{MODULUS, reduce};
/// use alloy_primitives::U256;
///
/// let m = MODULUS;
/// assert_eq!(reduce(&m), U256::ZERO);
/// assert_eq!(reduce(&(m + U256::from(5u64))), U256::from(5u64));
/// ```
#[inline]
pub fn reduce(x: &U256) -> U256 {
    // `%` reduces `x mod p`. U256's `Rem` impl panics on zero divisor, which
    // is impossible here (MODULUS is a compile-time non-zero constant).
    *x % MODULUS
}

/// Ensure `x` is in the field; return `Err` otherwise.
///
/// Prefer this to [`is_in_field`] at API boundaries so the caller gets a
/// typed error it can map into an HTTP 4xx response.
#[inline]
pub fn ensure_in_field(x: &U256) -> Result<(), FieldError> {
    if is_in_field(x) {
        Ok(())
    } else {
        Err(FieldError::OutOfRange(*x))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_small_values_are_in_field() {
        assert!(is_in_field(&U256::ZERO));
        assert!(is_in_field(&U256::from(1u64)));
        assert!(is_in_field(&U256::from(u64::MAX)));
    }

    #[test]
    fn modulus_and_above_are_out_of_field() {
        assert!(!is_in_field(&MODULUS));
        assert!(!is_in_field(&(MODULUS + U256::from(1u64))));
    }

    #[test]
    fn modulus_minus_one_is_in_field() {
        assert!(is_in_field(&(MODULUS - U256::from(1u64))));
    }

    #[test]
    fn reduce_wraps_around() {
        assert_eq!(reduce(&MODULUS), U256::ZERO);
        assert_eq!(reduce(&(MODULUS + U256::from(1u64))), U256::from(1u64));
        // already reduced stays put
        let v = U256::from(123_456u64);
        assert_eq!(reduce(&v), v);
    }

    #[test]
    fn ensure_in_field_returns_typed_error() {
        assert!(ensure_in_field(&U256::ZERO).is_ok());
        let err = ensure_in_field(&MODULUS).unwrap_err();
        assert_eq!(err, FieldError::OutOfRange(MODULUS));
    }

    #[test]
    fn modulus_decimal_matches_known_constant() {
        // Cross-check the U256 construction against the canonical decimal
        // string. If these disagree the limb packing above is wrong.
        let from_dec = U256::from_str_radix(MODULUS_DEC, 10).unwrap();
        assert_eq!(MODULUS, from_dec);
    }
}
