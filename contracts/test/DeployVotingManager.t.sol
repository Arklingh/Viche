// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {DeployVotingManager} from "../script/DeployVotingManager.s.sol";
import {Groth16Verifier} from "../src/verifier/Groth16Verifier.sol";

/// @title DeployVotingManagerTest
/// @notice Tests that the deploy script's verification-key guard fails CLOSED.
///
/// @dev The guard exists because `VotingManager.verifier` is immutable: wiring
///      in a verifier built from a trusted setup whose toxic waste survives is
///      not a recoverable mistake, and the dev pipeline produces exactly such a
///      verifier by default (public ptau + a hardcoded beacon string). The
///      failure mode that matters is the *quiet* one — a deploy that succeeds
///      when nobody configured anything — so that is the first case below.
///
///      These tests call `assertExpectedVerifier` directly with explicit
///      arguments instead of setting `VKEY_HASH` / `ALLOW_DEV_VERIFIER` and
///      running the whole script. That is deliberate: `vm.setEnv` mutates the
///      host process environment, which is not EVM state and so is not rolled
///      back between tests, and Foundry does not serialise test cases around
///      it. An earlier env-driven version of this file failed nondeterministic-
///      ally with values leaking between cases. The env plumbing left in
///      `run()` is two `vm.envOr` calls feeding this function; the decision
///      logic, which is what can actually be wrong, is fully covered here.
contract DeployVotingManagerTest is Test {
    DeployVotingManager internal script;
    Groth16Verifier internal verifier;
    bytes32 internal verifierCodehash;

    function setUp() public {
        script = new DeployVotingManager();
        verifier = new Groth16Verifier();
        verifierCodehash = address(verifier).codehash;
    }

    // =========================================================================
    // Fail-closed behaviour
    // =========================================================================

    /// @notice The headline case: nothing configured must NOT deploy.
    function test_RevertIf_VkeyHashUnset() public {
        vm.expectRevert(DeployVotingManager.VkeyHashNotConfigured.selector);
        script.assertExpectedVerifier(address(verifier), bytes32(0), false);
    }

    /// @notice A configured-but-wrong hash must abort, naming both values so
    ///         the operator can see what they actually got.
    function test_RevertIf_VkeyHashMismatch() public {
        bytes32 wrong = keccak256("not the verifier you are looking for");
        assertTrue(wrong != verifierCodehash, "sanity: the test hash must actually be wrong");

        vm.expectRevert(
            abi.encodeWithSelector(
                DeployVotingManager.VkeyHashMismatch.selector, wrong, verifierCodehash
            )
        );
        script.assertExpectedVerifier(address(verifier), wrong, false);
    }

    /// @notice An address with no code behind it must abort before the
    ///         VotingManager is built — otherwise the manager would be
    ///         permanently pointed at nothing. This is the `VERIFIER_ADDRESS`
    ///         typo case.
    function test_RevertIf_VerifierHasNoCode() public {
        address empty = address(0xDEAD);
        assertEq(empty.code.length, 0, "sanity: the address must really be empty");

        vm.expectRevert(
            abi.encodeWithSelector(DeployVotingManager.VerifierHasNoCode.selector, empty)
        );
        script.assertExpectedVerifier(empty, verifierCodehash, false);
    }

    /// @notice The no-code check runs even under the dev escape hatch: the
    ///         hatch waives the question of WHICH verifier, not whether there
    ///         is one at all.
    function test_RevertIf_VerifierHasNoCode_EvenWithAllowDevVerifier() public {
        address empty = address(0xDEAD);

        vm.expectRevert(
            abi.encodeWithSelector(DeployVotingManager.VerifierHasNoCode.selector, empty)
        );
        script.assertExpectedVerifier(empty, bytes32(0), true);
    }

    // =========================================================================
    // Accepting paths
    // =========================================================================

    /// @notice The matching hash passes.
    function test_AcceptsMatchingVkeyHash() public view {
        script.assertExpectedVerifier(address(verifier), verifierCodehash, false);
    }

    /// @notice Two separately deployed instances of the same verifier have the
    ///         same runtime codehash — i.e. the recorded hash identifies the
    ///         artifact, not the deployment. This is what makes it usable for
    ///         a pre-deployed `VERIFIER_ADDRESS`.
    function test_CodehashIdentifiesArtifactNotDeployment() public {
        Groth16Verifier other = new Groth16Verifier();
        assertTrue(address(other) != address(verifier), "sanity: distinct deployments");
        assertEq(address(other).codehash, verifierCodehash);

        script.assertExpectedVerifier(address(other), verifierCodehash, false);
    }

    /// @notice The dev escape hatch works, and only because it was asked for.
    ///
    /// @dev Deliberately paired with `test_RevertIf_VkeyHashUnset`: identical
    ///      arguments but for the flag, opposite outcome. If this ever passes
    ///      without the flag, the guard is not a guard.
    function test_AllowDevVerifierSkipsTheCheck() public view {
        script.assertExpectedVerifier(address(verifier), bytes32(0), true);
    }

    /// @notice The escape hatch overrides even a mismatched hash. It is an
    ///         explicit override, so it wins — pinned here so that is a
    ///         decision on record rather than an accident.
    function test_AllowDevVerifierOverridesAMismatchedHash() public view {
        script.assertExpectedVerifier(
            address(verifier), keccak256("deliberately wrong"), true
        );
    }
}
