// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

// =============================================================================
// !!! PLACEHOLDER VERIFIER — READ ME !!!
//
// This file is a deliberately-trivial stand-in so `forge build` and
// `forge test` succeed BEFORE the real Groth16 verifier exists. It is NOT
// secure: `verifyProof` always returns true, which is fine for the
// `MockVerifier`-based unit tests but would let anyone forge a ballot in a
// real deployment.
//
// `make circuits` OVERWRITES this entire file with the real snarkjs-generated
// Groth16 verifier (contract name, ABI and pairing math) at
//   contracts/src/verifier/Groth16Verifier.sol
// After that overwrite, the deploy script and tests automatically use the
// cryptographically-sound implementation.
//
// We commit this placeholder rather than gitignoring the verifier path so the
// project builds end-to-end without circom/snarkjs installed (e.g. in CI).
// If you want to be certain you're running the real verifier, check the file
// header: the snarkjs output starts with a banner comment containing
// "snarkjs" and "Groth16".
// =============================================================================

import {IVerifier} from "../IVerifier.sol";

/// @dev PLACEHOLDER. Replaced by `make circuits`. Do NOT deploy to mainnet as-is.
contract Groth16Verifier is IVerifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[3] calldata
    ) external pure override returns (bool) {
        // Intentionally permissive. The real verifier performs BN254 pairing
        // checks against the verifying key baked into this contract.
        return true;
    }
}
