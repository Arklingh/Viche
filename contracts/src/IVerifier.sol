// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title IVerifier
/// @notice Groth16 verifier interface consumed by `VotingManager`.
///
/// @dev The signature below is EXACTLY what `snarkjs zkey export solidityverifier`
///      emits (circom 2.x / snarkjs 0.7.x):
///
///          function verifyProof(
///              uint[2] calldata _pA,
///              uint[2][2] calldata _pB,
///              uint[2] calldata _pC,
///              uint[N] calldata _pubSignals
///          ) external view returns (bool);
///
///      Two things make this load-bearing rather than cosmetic:
///
///        1. The fixed-length `_pubSignals` (`uint[4]` for Viche — four public
///           signals, in this exact order:
///               [voteId, merkleRoot, nullifierHash, voteOption]
///           snarkjs generates a contract with the public-input count baked
///           into the type, so the count and the order are both part of the
///           4-byte selector and the pairing check respectively. A dynamic
///           `uint[]` here would compute a different selector and every call
///           would silently no-op; a wrong LENGTH would not even link.
///
///           `voteOption` is the fourth entry, and it is the reason this
///           interface widened from `uint[3]`. Before, the chosen option was
///           an unauthenticated `castVote` argument that no proof committed
///           to, so anyone watching the mempool could replay a pending
///           (proof, nullifier) pair under a different option, burn the
///           nullifier and flip the ballot. It is now bound into the proof —
///           see the BALLOT BINDING section of `circuits/circuits/vote.circom`.
///
///           If you change the circuit's public signals, this array's length
///           AND `VotingManager.castVote`'s assembly order must change with
///           it, in lockstep with a regenerated `Groth16Verifier`.
///
///        2. Pairing argument ordering. snarkjs lays out `_pB` as a 2x2 array
///           of `uint256` representing a single G2 point in the "uncompressed"
///           form `[ [X.c1, X.c0], [Y.c1, Y.c0] ]` (c0 is the imaginary part).
///           Keep this exact shape when re-serialising a proof for the call.
///
///      Because `VotingManager` depends on this *interface* (not the generated
///      contract), `forge build` works even before `make circuits` has emitted
///      the real `Groth16Verifier.sol`. Tests swap in a `MockVerifier`.
interface IVerifier {
    /// @param _pA         Groth16 proof, G1 point A.
    /// @param _pB         Groth16 proof, G2 point B (2x2 of uint256).
    /// @param _pC         Groth16 proof, G1 point C.
    /// @param _pubSignals Public inputs in circuit order:
    ///                    [voteId, merkleRoot, nullifierHash, voteOption].
    /// @return True iff the proof is valid for the given public inputs.
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals
    ) external view returns (bool);
}
