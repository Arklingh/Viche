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
///        1. The fixed-length `_pubSignals` (`uint[3]` for Viche — three public
///           signals: voteId, merkleRoot, nullifierHash). snarkjs generates a
///           contract with the public-input count baked into the type. A
///           dynamic `uint[]` here would compute a different 4-byte selector
///           and every call would silently no-op.
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
    ///                    [voteId, merkleRoot, nullifierHash].
    /// @return True iff the proof is valid for the given public inputs.
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[3] calldata _pubSignals
    ) external view returns (bool);
}
