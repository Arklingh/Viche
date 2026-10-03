//! Wire types for the relayer's HTTP API and the on-chain `castVote` call.
//!
//! These types are the contract between three components:
//!
//! 1. **Browser frontend** (Phase 3) — serialises a [`VoteRequest`] after
//!    generating the Groth16 proof in-page and `POST`s it to the relayer.
//! 2. **Relayer** (Phase 2) — deserialises the body, validates it, then
//!    repacks the proof into `castVote` calldata and broadcasts it.
//! 3. **Anyone reading logs** — the relayer returns a [`VoteResponse`] with
//!    the on-chain transaction hash and pending status.
//!
//! ## Proof encoding
//!
//! The contract's `castVote` decodes `proof` as
//! `abi.encode(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)` (the canonical
//! snarkjs shape). We carry the proof as **raw 0x-prefixed hex** on the wire
//! so the relayer can forward it byte-for-byte without re-serialisation risk.
//! See [`Proof`] for the exact layout and validation.

use crate::field::{ensure_in_field, FieldError};
use alloy_primitives::{Bytes, U256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The decoded length of a valid `castVote` proof blob, in bytes.
///
/// `abi.encode(uint256[2], uint256[2][2], uint256[2])` is:
/// - `pA`: 2 × 32 = 64 B
/// - `pB`: 4 × 32 = 128 B  (a 2×2 of uint256)
/// - `pC`: 2 × 32 = 64 B
///
/// Total = 256 B. There are no dynamic types, so no length prefixes or
/// offsets are emitted — the blob is exactly this size.
pub const PROOF_BYTES: usize = 256;

/// A Groth16 proof in the exact byte layout `VotingManager.castVote` expects.
///
/// Internally this is just [`Bytes`] (0x-prefixed hex on the wire), but the
/// [`Proof::from_bytes`] constructor validates the length up front so an
/// over-/under-sized proof is rejected at the deserialisation boundary rather
/// than failing inside the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Bytes", into = "Bytes")]
pub struct Proof(Bytes);

/// A proof was malformed (wrong length).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofError {
    /// The decoded byte length is not [`PROOF_BYTES`].
    #[error("invalid proof length: expected {expected} bytes, got {got}")]
    InvalidLength {
        /// The expected length ([`PROOF_BYTES`]).
        expected: usize,
        /// The actual length received.
        got: usize,
    },
}

impl Proof {
    /// Wrap an already-validated byte buffer in a [`Proof`].
    ///
    /// # Panics
    ///
    /// Panics if `bytes.len() != PROOF_BYTES`. Use [`Proof::from_bytes`] at
    /// API boundaries; this constructor is for tests/internal use where the
    /// length invariant has already been checked.
    #[inline]
    pub fn from_bytes_unchecked(bytes: Bytes) -> Self {
        assert_eq!(
            bytes.len(),
            PROOF_BYTES,
            "Proof::from_bytes_unchecked: length invariant violated"
        );
        Self(bytes)
    }

    /// Construct a [`Proof`] from raw bytes, validating the length.
    #[inline]
    pub fn from_bytes(bytes: Bytes) -> Result<Self, ProofError> {
        if bytes.len() != PROOF_BYTES {
            return Err(ProofError::InvalidLength {
                expected: PROOF_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// The raw proof bytes, ready for `castVote`'s `bytes calldata proof`.
    #[inline]
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }
}

impl TryFrom<Bytes> for Proof {
    type Error = ProofError;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl From<Proof> for Bytes {
    fn from(proof: Proof) -> Self {
        proof.0
    }
}

/// A nullifier hash returned by the circuit as one of the public signals.
///
/// This is `Poseidon(secret, voteId)`. On the wire we accept it as a
/// 0x-prefixed 32-byte hex string (the natural JSON form for a `bytes32`),
/// then validate that it is in the BN254 scalar field — `castVote` will be
/// rejected on-chain otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "U256", into = "U256")]
pub struct NullifierHash(U256);

impl NullifierHash {
    /// The underlying field element.
    #[inline]
    pub fn as_u256(&self) -> &U256 {
        &self.0
    }
}

impl TryFrom<U256> for NullifierHash {
    type Error = FieldError;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        ensure_in_field(&value)?;
        Ok(Self(value))
    }
}

impl From<NullifierHash> for U256 {
    fn from(value: NullifierHash) -> Self {
        value.0
    }
}

/// Request body for `POST /api/vote`.
///
/// Field order in JSON is alphabetical for stable snapshots; serde does not
/// require source order to match, so this is purely cosmetic.
///
/// # Validation
///
/// [`VoteRequest::validate`] performs the relayer-side pre-checks:
/// - `poll_id` is a non-zero `uint256` (polls start at 1 on-chain).
/// - `vote_option` fits in a `uint256`.
/// - `nullifier_hash` is in the BN254 scalar field.
/// - `proof` is exactly [`PROOF_BYTES`] long.
///
/// These catch malformed payloads *before* we spend gas broadcasting them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteRequest {
    /// Target poll id (`uint256` on-chain). MUST equal the circuit's `voteId`.
    ///
    /// Serialised as a decimal string for safe JSON big-number handling.
    pub poll_id: U256,
    /// The chosen option index. Validated on-chain against the poll's
    /// `numOptions`; the relayer only checks it's a sane `uint256`.
    pub vote_option: U256,
    /// `Poseidon(secret, poll_id)`, the per-poll double-voting tag.
    pub nullifier_hash: NullifierHash,
    /// `abi.encode(pA, pB, pC)` — exactly [`PROOF_BYTES`] bytes.
    pub proof: Proof,
}

/// Aggregate error for [`VoteRequest`] validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    /// `poll_id` was zero. Poll ids start at 1 on-chain.
    #[error("poll_id must be non-zero")]
    ZeroPollId,
    /// The nullifier hash was not a valid BN254 field element.
    #[error("invalid nullifier_hash: {0}")]
    InvalidNullifier(#[from] FieldError),
    /// The proof blob had the wrong length.
    #[error("invalid proof: {0}")]
    InvalidProof(#[from] ProofError),
}

impl VoteRequest {
    /// Run relayer-side pre-checks. Returns `Ok(())` if the payload is safe
    /// to forward on-chain.
    ///
    /// This is *not* a substitute for on-chain verification — the Groth16
    /// proof is still checked by the contract. It only filters out
    /// structurally-broken requests so we don't burn relayer gas on garbage.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.poll_id == U256::ZERO {
            return Err(ValidationError::ZeroPollId);
        }
        // nullifier_hash and proof are already validated at deserialise time
        // (their types enforce invariants), but be explicit and cheap here.
        ensure_in_field(self.nullifier_hash.as_u256())?;
        if self.proof.as_bytes().len() != PROOF_BYTES {
            return Err(ValidationError::InvalidProof(ProofError::InvalidLength {
                expected: PROOF_BYTES,
                got: self.proof.as_bytes().len(),
            }));
        }
        Ok(())
    }
}

/// Response body for `POST /api/vote`.
///
/// The relayer broadcasts the transaction asynchronously and returns its hash
/// immediately; the client polls the chain (or a `/status` endpoint, Phase 3)
/// to confirm inclusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteResponse {
    /// The broadcast transaction hash, hex-encoded.
    pub tx_hash: String,
    /// Lifecycle status. `broadcast` = accepted by the RPC node's mempool.
    pub status: VoteStatus,
}

/// Lifecycle of a relayer-submitted vote transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VoteStatus {
    /// Transaction was accepted by the mempool.
    Broadcast,
    /// Transaction was mined and succeeded.
    Mined,
    /// Transaction was mined but reverted.
    Reverted,
}

// =========================================================================
// Poll metadata wire types (Phase 3 — frontend fetches polls from relayer)
// =========================================================================

fn default_true() -> bool {
    true
}

/// A poll's public metadata, returned by the relayer's `GET /api/polls/:id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollData {
    /// On-chain poll id.
    pub poll_id: U256,
    /// Root of the Poseidon Merkle tree of eligible identity commitments.
    pub merkle_root: U256,
    /// Unix timestamp after which voting is rejected.
    pub deadline: U256,
    /// Number of vote options (options are indexed 0..num_options).
    pub num_options: U256,
    /// Total number of votes cast so far.
    pub total_votes: U256,
    /// Whether the poll is open: it has not been closed, cancelled or voided.
    /// This stays `true` past the deadline until an admin calls `closePoll`,
    /// so it says nothing about whether a vote would be accepted — see
    /// [`PollData::accepting_votes`].
    pub active: bool,
    /// Whether a vote submitted right now would be accepted: the poll is
    /// `active` **and** the chain's clock has not passed the deadline.
    /// Defaults to `true` when absent (an older relayer).
    #[serde(default = "default_true")]
    pub accepting_votes: bool,
    /// Off-chain pointer (or literal text) describing the poll question and
    /// option labels, as supplied at creation time. Not validated or
    /// interpreted here — only stored on-chain in the `PollCreated` event
    /// (never in contract storage), so the relayer recovers it from event
    /// logs rather than `getPoll`. Empty string if none was set or if it
    /// could not be recovered.
    #[serde(default)]
    pub metadata_uri: String,
}

/// Response for `GET /api/polls`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollListResponse {
    /// All polls on-chain.
    pub polls: Vec<PollData>,
}

/// Response for `GET /api/polls/:id/tally`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyResponse {
    /// The poll id.
    pub poll_id: U256,
    /// Per-option tallies (indices 0..num_options).
    pub option_tallies: Vec<U256>,
    /// Total votes across all options.
    pub total_votes: U256,
}

// =========================================================================
// Voter registration wire types (pre-poll commitment collection)
// =========================================================================
//
// A poll's whitelist is a fixed Merkle root chosen at `createPoll` time —
// the contract has no way to add members afterwards. So voters must submit
// their identity commitment (`Poseidon(secret)`, never the secret itself)
// to the relayer *before* the admin creates the next poll; the admin then
// builds the tree from the collected commitments (client-side, so the
// relayer never needs to hash anything) and the relayer stores the
// resulting `(merkle_root -> commitments)` mapping so voters can later fetch
// the leaf list needed to build their own membership proof. See
// `crate::registration` in `viche-relayer` for the server-side store.

/// Request body for `POST /api/register`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// `Poseidon(secret)` — the voter's identity commitment. Never the
    /// secret itself; the relayer only ever sees this one-way hash.
    pub commitment: U256,
}

/// Response for `POST /api/register`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// Number of commitments currently pending (not yet locked into a poll).
    pub total_pending: usize,
}

/// A plain list of identity commitments, returned by every endpoint that
/// hands back a leaf set: `GET /api/admin/registrations/pending`,
/// `POST /api/admin/registrations/snapshot`, and
/// `GET /api/polls/:id/registrations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentListResponse {
    /// Commitments in insertion order — the same order the admin's browser
    /// must insert them into the Merkle tree to reproduce a matching root.
    pub commitments: Vec<U256>,
}

/// Request body for `POST /api/admin/registrations/publish`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishRegistrationRequest {
    /// The Merkle root the admin's browser computed from the most recent
    /// `snapshot` response — becomes the lookup key for
    /// `GET /api/polls/:id/registrations`.
    pub merkle_root: U256,
}

/// Response for `POST /api/admin/registrations/publish`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishRegistrationResponse {
    /// Number of commitments stored under this root.
    pub commitment_count: usize,
}

// =========================================================================
// User-facing error text
// =========================================================================

/// Turn a relayer error response into a sentence a voter can act on.
///
/// The relayer answers failures with `{"code": "...", "message": "..."}`;
/// shown raw, that reads as `relayer rejected vote (409): {"code":...}`.
/// This recognises the situations a voter actually hits and says what
/// happened and what to do. Anything it doesn't recognise falls back to the
/// relayer's own message, cleaned up, and never to raw JSON.
pub fn friendly_relayer_error(status: u16, body: &str) -> String {
    #[derive(Deserialize)]
    struct ErrorBody {
        code: String,
        message: String,
    }

    let parsed = serde_json::from_str::<ErrorBody>(body).ok();
    let (code, message) = match &parsed {
        Some(b) => (b.code.as_str(), b.message.as_str()),
        None => ("", body.trim()),
    };
    let message = message.strip_prefix("on-chain revert: ").unwrap_or(message);
    let lower = message.to_lowercase();

    if lower.contains("voting has closed") {
        return "Voting on this poll has ended, so your vote was not counted.".into();
    }
    if lower.contains("not currently active") {
        return "This poll is no longer open for voting.".into();
    }
    if lower.contains("already voted") {
        return "You have already voted in this poll. Each voter gets one vote.".into();
    }
    if lower.contains("proof was rejected") {
        return "Your vote could not be verified. Reload the page and try again; if it keeps \
                failing, contact the poll organiser."
            .into();
    }
    if lower.contains("does not exist") && lower.contains("poll") {
        return "This poll no longer exists. Reload the page to refresh the list.".into();
    }
    if lower.contains("option is not valid") {
        return "That option is not valid for this poll. Pick another one.".into();
    }

    match (status, code) {
        // These already carry a complete sentence written for people.
        (_, "NOT_ELIGIBLE") | (_, "REGISTRATION_CAP_REACHED") => capitalise(message),
        (401, _) => "The admin API key was missing or wrong. Check it and try again.".into(),
        (429, _) => "Too many requests from your connection. Wait a minute and try again.".into(),
        (_, "GAS_PRICE_TOO_HIGH") | (_, "PROVIDER_ERROR") | (_, "CONTRACT_ERROR")
        | (502..=504, _) => "The network is busy or the relayer cannot reach it right now. \
                             Nothing was submitted; try again in a minute."
            .into(),
        (500..=599, _) => "Something went wrong on the relayer. Try again; if it keeps \
                           happening, contact the poll organiser."
            .into(),
        _ if message.is_empty() => format!("The relayer rejected the request (status {status})."),
        _ => capitalise(message),
    }
}

/// Upper-case the first character and make sure the sentence ends in a full
/// stop, so relayer messages read like the hand-written ones above.
fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    let mut out = match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => return String::new(),
    };
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 256-byte proof filled with a repeating byte pattern.
    fn dummy_proof_bytes(fill: u8) -> Bytes {
        Bytes::from(vec![fill; PROOF_BYTES])
    }

    #[test]
    fn proof_accepts_exact_length() {
        let p = Proof::from_bytes(dummy_proof_bytes(0xAB)).unwrap();
        assert_eq!(p.as_bytes().len(), PROOF_BYTES);
    }

    #[test]
    fn proof_rejects_wrong_length() {
        let too_short = Bytes::from(vec![0u8; PROOF_BYTES - 1]);
        let too_long = Bytes::from(vec![0u8; PROOF_BYTES + 1]);
        assert!(matches!(
            Proof::from_bytes(too_short),
            Err(ProofError::InvalidLength {
                expected: PROOF_BYTES,
                got: _
            })
        ));
        assert!(matches!(
            Proof::from_bytes(too_long),
            Err(ProofError::InvalidLength {
                expected: PROOF_BYTES,
                got: _
            })
        ));
    }

    #[test]
    fn proof_round_trips_through_serde_as_hex() {
        let p = Proof::from_bytes(dummy_proof_bytes(0x01)).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        // Bytes serialises as 0x-prefixed hex.
        assert!(json.starts_with("\"0x"));
        let back: Proof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn nullifier_rejects_out_of_field_value() {
        use crate::field::MODULUS;
        let err = NullifierHash::try_from(MODULUS).unwrap_err();
        assert_eq!(err, FieldError::OutOfRange(MODULUS));
    }

    #[test]
    fn nullifier_accepts_in_field_value() {
        let n = NullifierHash::try_from(U256::from(42u64)).unwrap();
        assert_eq!(*n.as_u256(), U256::from(42u64));
    }

    #[test]
    fn vote_request_validates_happy_path() {
        let req = VoteRequest {
            poll_id: U256::from(1u64),
            vote_option: U256::from(2u64),
            nullifier_hash: NullifierHash::try_from(U256::from(0x1234u64)).unwrap(),
            proof: Proof::from_bytes(dummy_proof_bytes(0x00)).unwrap(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn vote_request_rejects_zero_poll_id() {
        let req = VoteRequest {
            poll_id: U256::ZERO,
            vote_option: U256::ZERO,
            nullifier_hash: NullifierHash::try_from(U256::from(1u64)).unwrap(),
            proof: Proof::from_bytes(dummy_proof_bytes(0x00)).unwrap(),
        };
        assert_eq!(req.validate(), Err(ValidationError::ZeroPollId));
    }

    #[test]
    fn vote_request_round_trips_through_json() {
        let req = VoteRequest {
            poll_id: U256::from(7u64),
            vote_option: U256::from(1u64),
            nullifier_hash: NullifierHash::try_from(U256::from(0xDEADu64)).unwrap(),
            proof: Proof::from_bytes(dummy_proof_bytes(0xAB)).unwrap(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: VoteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn register_request_round_trips_through_json() {
        let req = RegisterRequest {
            commitment: U256::from(0xBEEFu64),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: RegisterRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn commitment_list_response_round_trips_through_json() {
        let resp = CommitmentListResponse {
            commitments: vec![U256::from(1u64), U256::from(2u64)],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: CommitmentListResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn publish_registration_request_round_trips_through_json() {
        let req = PublishRegistrationRequest {
            merkle_root: U256::from(0xF00Du64),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: PublishRegistrationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    // ---- friendly_relayer_error ------------------------------------------

    fn revert(msg: &str) -> String {
        format!(r#"{{"code":"ON_CHAIN_REVERT","message":"on-chain revert: {msg}"}}"#)
    }

    #[test]
    fn a_closed_poll_is_explained_without_json_or_prefixes() {
        let msg = friendly_relayer_error(409, &revert("voting has closed for poll 1"));
        assert!(msg.contains("ended"), "{msg}");
        assert!(!msg.contains('{') && !msg.contains("on-chain"), "{msg}");
    }

    #[test]
    fn the_common_voter_reverts_each_get_their_own_advice() {
        let double = friendly_relayer_error(409, &revert("you have already voted in this poll"));
        assert!(double.contains("one vote"), "{double}");

        let proof = friendly_relayer_error(
            409,
            &revert("the submitted proof was rejected (it must have been generated for this exact poll)"),
        );
        assert!(proof.contains("Reload"), "{proof}");

        let ended = friendly_relayer_error(409, &revert("this poll is not currently active"));
        assert!(ended.contains("no longer open"), "{ended}");

        let gone = friendly_relayer_error(409, &revert("poll 9 does not exist"));
        assert!(gone.contains("no longer exists"), "{gone}");
    }

    #[test]
    fn transport_trouble_says_nothing_was_submitted() {
        let body = r#"{"code":"PROVIDER_ERROR","message":"provider error: connection refused"}"#;
        let msg = friendly_relayer_error(502, body);
        assert!(msg.contains("Nothing was submitted"), "{msg}");
        assert!(!msg.contains("connection refused"), "internals must not leak: {msg}");

        assert!(friendly_relayer_error(429, "{}").contains("Wait a minute"));
        assert!(friendly_relayer_error(500, "oops").contains("Something went wrong"));
    }

    #[test]
    fn eligibility_messages_pass_through_as_sentences() {
        let body = r#"{"code":"NOT_ELIGIBLE","message":"that commitment is not on the allowlist"}"#;
        assert_eq!(
            friendly_relayer_error(403, body),
            "That commitment is not on the allowlist."
        );
    }

    #[test]
    fn unknown_failures_never_surface_raw_json() {
        let body = r#"{"code":"SOMETHING_NEW","message":"a brand new problem"}"#;
        assert_eq!(friendly_relayer_error(400, body), "A brand new problem.");
        // Not JSON at all.
        assert_eq!(friendly_relayer_error(400, "bad thing"), "Bad thing.");
        assert!(friendly_relayer_error(400, "").contains("status 400"));
    }

    #[test]
    fn poll_data_from_an_older_relayer_defaults_to_accepting_votes() {
        let json = r#"{"poll_id":"0x1","merkle_root":"0x2","deadline":"0x3","num_options":"0x2","total_votes":"0x0","active":true}"#;
        let p: PollData = serde_json::from_str(json).unwrap();
        assert!(p.accepting_votes);
    }
}
