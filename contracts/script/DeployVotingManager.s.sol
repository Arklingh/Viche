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
contract DeployVotingManager is Script {
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
}
