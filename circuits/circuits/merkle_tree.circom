// =============================================================================
// merkle_tree.circom — Poseidon Merkle inclusion checker for Viche.
//
// This is the whitelist primitive. Each eligible voter registers a
// *commitment* `Poseidon(secret)` as a leaf. At vote time the prover supplies
// the sibling hashes and the left/right path that locates their leaf, and the
// circuit re-derives the root; the main `vote.circom` circuit then constrains
// the recomputed root to equal the public `merkleRoot`.
//
// Conventions (these MUST match the off-chain tree builder in
// `circuits/scripts/gen_input.js` and the future Rust impl in
// `crates/viche-core`, otherwise proofs won't verify on-chain):
//
//   * Hash function  : Poseidon over the BN254 scalar field (circomlib params).
//   * Pair hashing    : `parent = Poseidon(leftChild, rightChild)`.
//   * Zero leaves     : the empty-tree is built from a chain of "zero hashes",
//                       where `zeros[0] = 0` and `zeros[i] = Poseidon(zeros[i-1], zeros[i-1])`.
//                       The off-chain builder MUST use this same chain so a
//                       sparse tree and a dense one agree on the root.
//   * pathIndices[i] : 0  -> the prover's current node is the LEFT child at
//                            level `i`, so `pathElements[i]` is its RIGHT sibling.
//                      1  -> the prover's node is the RIGHT child, so
//                            `pathElements[i]` is its LEFT sibling.
//
// `BinarySwitcher` below is a constant-fan-in 2 selector that also enforces
// `pathIndices` is boolean via the `s*(s-1) === 0` constraint.
// =============================================================================

pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";

/// If `s == 0`, output `[in[0], in[1]]`; if `s == 1`, output `[in[1], in[0]]`.
template BinarySwitcher() {
    signal input in[2];
    signal input s;
    signal output out[2];

    signal aux;

    s * (s - 1) === 0;
    aux <== (in[1] - in[0]) * s;
    out[0] <== in[0] + aux;
    out[1] <== in[1] - aux;
}

/// Recomputes the Merkle root of a binary Poseidon tree of depth `nLevels`,
/// given a leaf and its authentication path, without revealing the leaf's
/// position relative to other (private) leaves.
///
/// @param nLevels Tree depth (Viche default: 20 => up to 2^20 leaves).
template MerkleTreeInclusionCheck(nLevels) {
    // The prover's leaf (already an identity commitment in `vote.circom`).
    signal input leaf;
    // Sibling hash at each level of the path.
    signal input pathElements[nLevels];
    // 0/1 selector: is the prover's node the left (0) or right (1) child?
    signal input pathIndices[nLevels];

    // Recomputed tree root; constrained against the public `merkleRoot`
    // by the caller (`vote.circom`).
    signal output root;

    // Walk up the tree level by level. `computedHash` is the rolling hash of
    // the prover's subtree, starting from the leaf itself.
    component muxes[nLevels];
    component hashers[nLevels];
    signal computedHash[nLevels + 1];

    computedHash[0] <== leaf;

    for (var i = 0; i < nLevels; i++) {
        // Order the two children for this level so that index 0 == left child
        // and index 1 == right child, regardless of which one is ours.
        muxes[i] = BinarySwitcher();
        muxes[i].in[0] <== computedHash[i];    // ours, by default on the left
        muxes[i].in[1] <== pathElements[i];    // the sibling
        muxes[i].s <== pathIndices[i];

        // parent = Poseidon(leftChild, rightChild)
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxes[i].out[0];
        hashers[i].inputs[1] <== muxes[i].out[1];

        computedHash[i + 1] <== hashers[i].out;
    }

    root <== computedHash[nLevels];
}
