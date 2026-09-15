// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";

import {VotingManager} from "../src/VotingManager.sol";
import {Groth16Verifier} from "../src/verifier/Groth16Verifier.sol";

import {console2} from "forge-std/console2.sol";

/// @title DeployVotingManager
/// @notice Forge deployment script. Two-stage:
///
///   forge script script/DeployVotingManager.s.sol \
///        --rpc-url $RPC_URL --broadcast \
///        --verify --verifier etherscan --verifier-url $VERIFIER_URL
///
/// Behaviour:
///   * If VERIFIER_ADDRESS is set in the env, deploy `VotingManager` against
///     that already-deployed verifier (useful when the verifier is deployed
///     in a prior step or shared across contracts).
///   * Otherwise deploy a freshly generated `Groth16Verifier` first. This
///     contract is emitted by `make circuits` into
///     `src/verifier/Groth16Verifier.sol`; the script will not compile if
///     `make circuits` has not been run yet — which is the intended guard.
///
/// ## The verification-key guard
///
/// A Groth16 verifier is only as trustworthy as the trusted setup that
/// produced its verification key. Viche's development pipeline builds that key
/// from the public Hermez `ptau` plus a *hardcoded, non-secret* beacon string
/// (`circuits/scripts/compile.sh`, step 4). Anybody can reproduce that setup's
/// toxic waste, and anybody who does can forge proofs for arbitrary votes that
/// verify perfectly on-chain. Since `VotingManager.verifier` is `immutable`,
/// deploying the wrong verifier is not a mistake you can patch afterwards —
/// the fix is a whole new deployment and a migration of every poll.
///
/// So this script refuses to deploy a verifier whose identity has not been
/// explicitly vouched for:
///
///   * `VKEY_HASH` — the expected `keccak256` of the verifier's deployed
///     runtime bytecode. Required. Unset or mismatched => the script reverts
///     and nothing is broadcast.
///   * `ALLOW_DEV_VERIFIER=true` — the ONLY escape hatch, for anvil/local
///     work. It skips the comparison and shouts about it. Never set it
///     against a network you care about.
///
/// ### Why hash the runtime code rather than the vkey constants
///
/// The generated verifier embeds its verification key as `constant`s consumed
/// inside an `assembly` block. It exposes no getters, and the file is
/// overwritten wholesale by `make circuits`, so there is nowhere sound to add
/// them without the change being clobbered on the next build. Reading the key
/// back out of a deployed instance would mean parsing bytecode at fixed
/// offsets — brittle, and silently wrong if snarkjs changes its template.
///
/// The runtime codehash is the honest alternative: it covers the vkey
/// constants along with everything else, cannot be spoofed by a contract that
/// merely claims to be the right verifier, and is one `EXTCODEHASH`. The
/// tradeoff, stated plainly so nobody is surprised by it: the hash also
/// changes when the compiler version or optimiser settings change, even though
/// the underlying key did not. That makes it a pin on the exact artifact you
/// reviewed, which is the stronger property for a deploy gate, but it does
/// mean the recorded value must be regenerated (and re-reviewed) whenever the
/// build changes. See `docs/trusted-setup-ceremony.md` for how to compute and
/// record it.
contract DeployVotingManager is Script {
    /// @dev Thrown when `VKEY_HASH` is absent and the dev escape hatch is off.
    error VkeyHashNotConfigured();
    /// @dev Thrown when the deployed verifier is not the expected artifact.
    error VkeyHashMismatch(bytes32 expected, bytes32 actual);
    /// @dev Thrown when `VERIFIER_ADDRESS` points at an account with no code.
    error VerifierHasNoCode(address verifier);

    /// @dev Read from the environment so the same script works for local
    ///      anvil, testnet and mainnet without code changes.
    function run() external returns (VotingManager voting, address verifierAddr) {
        address existing = vm.envOr("VERIFIER_ADDRESS", address(0));

        vm.startBroadcast();

        if (existing == address(0)) {
            // `make circuits` must have run first.
            Groth16Verifier verifier = new Groth16Verifier();
            verifierAddr = address(verifier);
        } else {
            verifierAddr = existing;
        }

        // Gate BEFORE the VotingManager is constructed: its `verifier` is
        // immutable, so a manager built against an unvouched-for verifier is
        // permanently wrong. Reverting here means nothing is broadcast at all
        // (forge simulates the whole script first).
        //
        // The env is read HERE and the decision is made in a function that
        // takes its inputs explicitly, so the guard's logic can be tested
        // without `vm.setEnv` — which mutates the host process environment and
        // therefore races with every other test in the run.
        assertExpectedVerifier(
            verifierAddr,
            vm.envOr("VKEY_HASH", bytes32(0)),
            vm.envOr("ALLOW_DEV_VERIFIER", false)
        );

        voting = new VotingManager(verifierAddr);

        require(address(voting.verifier()) == verifierAddr, "Verifier address mismatch");

        vm.stopBroadcast();

        // Forge picks up script-formatted logs for downstream tooling.
        // fmt: off
        console2.log("Groth16Verifier  :", verifierAddr);
        console2.log("VotingManager    :", address(voting));
        console2.log("Deployer (owner) :", voting.owner());
        // fmt: on
    }

    /// @notice Fail closed unless the verifier at `verifierAddr` is the exact
    ///         artifact the operator configured.
    ///
    /// @dev Fails closed in every direction: no code at the address, no
    ///      `expectedVkeyHash` configured (zero is treated as unset, never as
    ///      a wildcard), or a hash that does not match. The only way past is
    ///      `allowDevVerifier`, which is loud on purpose.
    ///
    ///      Takes its configuration as arguments rather than reading the env
    ///      itself so it can be unit-tested deterministically — see
    ///      `test/DeployVotingManager.t.sol`. `run()` does the env reading.
    ///
    /// @param verifierAddr     The verifier about to be wired into VotingManager.
    /// @param expectedVkeyHash Expected keccak256 of its runtime code; zero means
    ///                         "not configured", which is a hard failure.
    /// @param allowDevVerifier Skip the comparison. Local/anvil development only.
    function assertExpectedVerifier(
        address verifierAddr,
        bytes32 expectedVkeyHash,
        bool allowDevVerifier
    ) public view {
        if (verifierAddr.code.length == 0) revert VerifierHasNoCode(verifierAddr);

        // EXTCODEHASH of the deployed runtime code.
        bytes32 actual = verifierAddr.codehash;

        // Always print it, including on the happy path: this is how an
        // operator obtains the value to record after a real ceremony.
        console2.log("Verifier codehash:");
        console2.logBytes32(actual);

        if (allowDevVerifier) {
            // fmt: off
            console2.log("");
            console2.log("!!! ALLOW_DEV_VERIFIER=true - verification-key check SKIPPED !!!");
            console2.log("    This verifier may come from a trusted setup whose toxic waste");
            console2.log("    still exists. Anyone holding it can forge unlimited votes.");
            console2.log("    Local/anvil development only. Never use on a real network.");
            console2.log("");
            // fmt: on
            return;
        }

        bytes32 expected = expectedVkeyHash;

        if (expected == bytes32(0)) {
            // fmt: off
            console2.log("");
            console2.log("VKEY_HASH is not set. Refusing to deploy.");
            console2.log("  Set VKEY_HASH to the codehash printed above once you have");
            console2.log("  verified the verifier came from a trusted setup you accept");
            console2.log("  (see docs/trusted-setup-ceremony.md), or set");
            console2.log("  ALLOW_DEV_VERIFIER=true for local development only.");
            console2.log("");
            // fmt: on
            revert VkeyHashNotConfigured();
        }

        if (expected != actual) {
            // fmt: off
            console2.log("");
            console2.log("Verifier codehash does NOT match VKEY_HASH. Refusing to deploy.");
            console2.log("  This means the verifier being deployed is not the artifact you");
            console2.log("  vouched for - a different trusted setup, a different compiler");
            console2.log("  build, or a stale src/verifier/Groth16Verifier.sol. Do not");
            console2.log("  'fix' this by copying the new hash into VKEY_HASH without");
            console2.log("  working out why it changed.");
            console2.log("  expected:");
            console2.logBytes32(expected);
            console2.log("  actual:");
            console2.logBytes32(actual);
            console2.log("");
            // fmt: on
            revert VkeyHashMismatch(expected, actual);
        }
    }
}
