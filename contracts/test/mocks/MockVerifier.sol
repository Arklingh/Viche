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

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[3] calldata
    ) external view override returns (bool) {
        return shouldAccept;
    }
}
