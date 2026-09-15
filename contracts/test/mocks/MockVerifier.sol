// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IVerifier} from "../../src/IVerifier.sol";

/// @title MockVerifier
/// @notice Deterministic stand-in for the generated `Groth16Verifier` used in
///         unit tests. The real verifier does ~250k gas of pairing math; we
///         don't want to drag the prover into every `forge test` run, so we
///         let tests toggle acceptance with `setShouldAccept` and exercise the
///         `VotingManager` control flow (lifecycle, option bounds, nullifier
///         dedup, error paths) without touching cryptography.
contract MockVerifier is IVerifier {
    /// @dev Public so tests can flip it. Default true so a happy-path test
    ///      doesn't have to set anything.
    bool public shouldAccept = true;

    function setShouldAccept(bool v) external {
        shouldAccept = v;
    }

    /// @dev The `uint256[4]` public-signal array (not `[3]`) mirrors the
    ///      circuit's four public signals — [voteId, merkleRoot,
    ///      nullifierHash, voteOption]. The length is part of the selector, so
    ///      this must track `IVerifier` exactly or `VotingManager` would call
    ///      into nothing. Unit tests deliberately ignore the contents; the
    ///      real binding of `voteOption` to the proof is exercised against the
    ///      genuine verifier in `VotingManagerIntegration.t.sol`.
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[4] calldata
    ) external view override returns (bool) {
        return shouldAccept;
    }
}
