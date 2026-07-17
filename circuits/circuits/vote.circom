// =============================================================================
// vote.circom — Viche anonymous-ballot Groth16 circuit.
//
// WHAT THE PROVER PROVES:
//   "I know a `secret` whose identity commitment `Poseidon(secret)` is a leaf
//    in the public Merkle tree with root `merkleRoot`, AND I have not yet
//    voted in poll `voteId`, evidenced by the per-poll nullifier
//    `nullifierHash = Poseidon(secret, voteId)`."
//
// ANONYMITY MODEL:
//   The voter's *identity* is anonymous — only `voteId`, `merkleRoot` and
//   `nullifierHash` are public. `secret`, `pathElements` and `pathIndices`
//   stay private. Without `pathElements`/`pathIndices` an observer cannot
//   tell which leaf in the (public) Merkle tree belongs to the voter, so
//   even a fully-synchronised node cannot link a ballot to an address.
//
//   The *chosen option* itself is NOT private — `voteOption` is submitted in
//   the clear by the relayer and tallied on-chain. Hiding the choice requires
//   an additional encryption layer and is explicitly out of scope for Viche v1.
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
//        pubSignals = [voteId, merkleRoot, nullifierHash]
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
    // See the file header: the order of these three is part of the verifier
    // contract's ABI and must not change without regenerating everything.
    signal input voteId;         // == on-chain pollId
    signal input merkleRoot;     // public whitelist root
    signal input nullifierHash;  // Poseidon(secret, voteId)

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
}

// Viche default: depth-20 tree (up to ~1M voters). Compile-time parameter;
// changing it requires regenerating the trusted setup (the zkey) and the
// verifier contract.
component main {public [voteId, merkleRoot, nullifierHash]} = Vote(20);
