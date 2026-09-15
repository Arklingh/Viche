// =============================================================================
// vote.circom — Viche anonymous-ballot Groth16 circuit.
//
// WHAT THE PROVER PROVES:
//   "I know a `secret` whose identity commitment `Poseidon(secret)` is a leaf
//    in the public Merkle tree with root `merkleRoot`, AND I have not yet
//    voted in poll `voteId`, evidenced by the per-poll nullifier
//    `nullifierHash = Poseidon(secret, voteId)`, AND I am casting this ballot
//    for option `voteOption` specifically."
//
// ANONYMITY MODEL:
//   The voter's *identity* is anonymous — only `voteId`, `merkleRoot`,
//   `nullifierHash` and `voteOption` are public. `secret`, `pathElements` and
//   `pathIndices` stay private. Without `pathElements`/`pathIndices` an
//   observer cannot tell which leaf in the (public) Merkle tree belongs to the
//   voter, so even a fully-synchronised node cannot link a ballot to an
//   address.
//
//   The *chosen option* itself is NOT private — `voteOption` is submitted in
//   the clear and tallied on-chain. Hiding the choice requires an additional
//   encryption layer and is explicitly out of scope for Viche v1. Being public
//   is not the same as being unauthenticated, though — see BALLOT BINDING.
//
// BALLOT BINDING (why `voteOption` is a public *input* and not a bare
// calldata argument):
//   `voteOption` used to travel to `VotingManager.castVote` as a plain
//   argument that no proof committed to. That made every pending ballot
//   malleable by anyone who could see it:
//
//     * the relayer could silently rewrite the option before broadcasting; and
//     * worse, `castVote` is permissionless and proofs sit in the public
//       mempool, so ANY observer could copy a pending `(proof, nullifier)`
//       pair, resubmit it with a different `voteOption` at a higher gas price,
//       burn the nullifier, and leave the real voter's transaction reverting
//       with `AlreadyVoted`. Anyone could flip anyone's vote.
//
//   Making `voteOption` a public input folds it into the Groth16 pairing
//   check: the verifier recomputes the public-input commitment from the
//   supplied signals, so a proof produced for option X simply does not verify
//   against option Y. Rewriting the option requires re-proving, which requires
//   the voter's `secret`.
//
//   The `voteOptionSq <== voteOption * voteOption` constraint below exists so
//   that no compiler pass can ever treat `voteOption` as a dead signal. It is
//   one multiplication — the cheapest possible R1CS constraint — and it buys
//   a guarantee that the signal is genuinely consumed by the constraint
//   system rather than only named in the witness header.
//
//   Measured, so the reasoning is not folklore: with circom 2.2.3 the input
//   keeps its witness slot and `public inputs: 4` even when nothing reads it,
//   because the main component's public inputs are pinned into the witness
//   layout before simplification runs. So the constraint is defence in depth
//   against a future compiler version or optimisation level that is less
//   generous, not a fix for observed 2.2.3 behaviour. Do not delete it on the
//   grounds that "it compiles fine without it" — that is precisely the
//   observation it is insuring against.
//
//   Whatever you change here, check `snarkjs r1cs info` / the exported vkey's
//   `nPublic` afterwards: it must read 4, and `IC` in the generated verifier
//   must have 5 entries (nPublic + 1).
//
//   Note on bounds: the circuit deliberately does NOT range-check
//   `voteOption` against the poll's option count. That bound lives on-chain
//   (`InvalidVoteOption` in `VotingManager.castVote`), where `numOptions` is
//   actually known; baking a compile-time maximum into the circuit would
//   force a new trusted setup every time a poll wanted more options.
//
// DOUBLE-VOTING:
//   Two valid ballots in the same poll would require the same `secret`, which
//   forces `nullifierHash` to repeat. `VotingManager.sol` rejects duplicate
//   nullifiers. The nullifier reveals nothing about `secret` thanks to
//   Poseidon's one-wayness.
//
// PUBLIC-SIGNAL ORDERING (load-bearing):
//   circom/snarkjs expose public inputs in the order they're declared, with
//   NO outputs after them. So the on-chain `pubSignals` array passed to the
//   Groth16 verifier MUST be exactly:
//
//        pubSignals = [voteId, merkleRoot, nullifierHash, voteOption]
//
//   `voteOption` is APPENDED rather than slotted in next to `voteId`, on
//   purpose: every existing consumer that indexes into `publicSignals`
//   (`gen_proof.js`, the browser prover's nullifier extraction, the Foundry
//   test vectors) keeps the meaning of indices 0-2, so widening the array is
//   the only behavioural change. Inserting it anywhere else would silently
//   shift `merkleRoot`/`nullifierHash` under code that still reads the old
//   positions.
//
//   `VotingManager.castVote` assembles the array in this same order. If you
//   reorder the inputs below, update both the contract AND `gen_input.js`
//   AND the relayer proof-packing code, or verification will silently fail.
//
// FIELD REMINDER:
//   Every signal must lie in [0, BN254_SCALAR_FIELD) =
//   0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001.
//   The frontend must reduce `secret` and `pollId` into this range before
//   building the witness.
// =============================================================================

pragma circom 2.1.6;

include "./merkle_tree.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/// Anonymous ballot circuit.
///
/// @param MERKLE_TREE_DEPTH Whitelist tree depth. Viche default is 20.
template Vote(MERKLE_TREE_DEPTH) {
    // ---- Private inputs (voter-only) ---------------------------------------
    // A uniform-random scalar in [0, BN254_SCALAR_FIELD). This is the only
    // long-lived secret per voter; losing it forfeits the ability to vote,
    // leaking it lets anyone impersonate the voter.
    signal input secret;

    // Authentication path proving `Poseidon(secret)` is a tree leaf.
    signal input pathElements[MERKLE_TREE_DEPTH];
    signal input pathIndices[MERKLE_TREE_DEPTH];

    // ---- Public inputs (inspected on-chain) --------------------------------
    // See the file header: the order of these four is part of the verifier
    // contract's ABI and must not change without regenerating everything.
    signal input voteId;         // == on-chain pollId
    signal input merkleRoot;     // public whitelist root
    signal input nullifierHash;  // Poseidon(secret, voteId)
    signal input voteOption;     // index of the chosen option (see BALLOT BINDING)

    // -------------------------------------------------------------------------
    // 1) Identity commitment = Poseidon(secret). This is the value that was
    //    registered off-chain as the voter's Merkle leaf.
    // -------------------------------------------------------------------------
    component commitmentHasher = Poseidon(1);
    commitmentHasher.inputs[0] <== secret;
    signal commitment <== commitmentHasher.out;

    // -------------------------------------------------------------------------
    // 2) Merkle membership. The root recomputed from the supplied path MUST
    //    equal the public `merkleRoot`, or the proof is invalid. This binds
    //    the ballot to a specific whitelist snapshot (and therefore a poll).
    // -------------------------------------------------------------------------
    component tree = MerkleTreeInclusionCheck(MERKLE_TREE_DEPTH);
    tree.leaf <== commitment;
    tree.pathElements <== pathElements;
    tree.pathIndices <== pathIndices;
    merkleRoot === tree.root;

    // -------------------------------------------------------------------------
    // 3) Nullifier = Poseidon(secret, voteId). Deterministic per
    //    (voter, poll) yet one-way, so it can be published as the
    //    double-voting tag without leaking identity.
    // -------------------------------------------------------------------------
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== voteId;
    nullifierHash === nullifierHasher.out;

    // -------------------------------------------------------------------------
    // 4) Ballot binding. `voteOption` carries no witness of its own — its whole
    //    job is to be part of the public-input commitment the Groth16 verifier
    //    recomputes, so a proof minted for one option cannot be replayed
    //    against another (see BALLOT BINDING in the file header).
    //
    //    This single multiplication is what keeps the signal genuinely inside
    //    the R1CS rather than merely named in the witness header, so no
    //    simplification pass can ever treat it as dead and drop it from the
    //    verification key (which would quietly restore the malleability bug).
    //    `voteOptionSq` is never read again — that is expected and intentional.
    // -------------------------------------------------------------------------
    signal voteOptionSq <== voteOption * voteOption;
}

// Viche default: depth-20 tree (up to ~1M voters). Compile-time parameter;
// changing it requires regenerating the trusted setup (the zkey) and the
// verifier contract.
component main {public [voteId, merkleRoot, nullifierHash, voteOption]} = Vote(20);
