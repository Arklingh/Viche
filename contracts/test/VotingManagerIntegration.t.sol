// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VotingManager} from "../src/VotingManager.sol";
import {Groth16Verifier} from "../src/verifier/Groth16Verifier.sol";

/// @title VotingManagerIntegrationTest
/// @notice End-to-end cryptographic integration test pairing `VotingManager`
///         with the actual compiled `Groth16Verifier` contract using a real
///         Groth16 proof generated from `vote.circom`.
contract VotingManagerIntegrationTest is Test {
    VotingManager internal voting;
    Groth16Verifier internal realVerifier;

    // Real public signals from proof-demo (gen_proof.js).
    //
    // Circuit order is [voteId, merkleRoot, nullifierHash, voteOption]; the
    // option is part of that list, so a proof is valid for ONE option only.
    // `VOTE_OPTION` below is what `gen_input.js` proved for (its
    // `VOTE_OPTION` env default) — change one and you must change the other.
    uint256 internal constant VOTE_ID = 1;
    bytes32 internal constant MERKLE_ROOT = bytes32(uint256(18142334754527230829434618760706122867182291645357706712475860565891430848844));
    bytes32 internal constant NULLIFIER_HASH = bytes32(uint256(4187152743772995393318417670842768441279259923326005547157850571084256757975));
    uint256 internal constant VOTE_OPTION = 1;

    function setUp() public {
        realVerifier = new Groth16Verifier();
        voting = new VotingManager(address(realVerifier));
    }

    function _getMerkleRoot() internal view returns (bytes32) {
        string memory path = "circuits/build/test_proof.json";
        if (vm.exists(path)) {
            string memory json = vm.readFile(path);
            uint256 root = vm.parseJsonUint(json, ".merkleRoot");
            return bytes32(root);
        }
        return MERKLE_ROOT;
    }

    function _getNullifierHash() internal view returns (bytes32) {
        string memory path = "circuits/build/test_proof.json";
        if (vm.exists(path)) {
            string memory json = vm.readFile(path);
            uint256 nullifier = vm.parseJsonUint(json, ".nullifierHash");
            return bytes32(nullifier);
        }
        return NULLIFIER_HASH;
    }

    /// @dev The option the real proof was generated for. Every happy-path call
    ///      below must use this exact value — the proof is bound to it.
    function _getVoteOption() internal view returns (uint256) {
        string memory path = "circuits/build/test_proof.json";
        if (vm.exists(path)) {
            string memory json = vm.readFile(path);
            return vm.parseJsonUint(json, ".voteOption");
        }
        return VOTE_OPTION;
    }

    /// @dev Helper to construct the exact 256-byte `abi.encode(pA, pB, pC)` payload
    ///      from the real Groth16 proof points.
    function _realProof() internal view returns (bytes memory) {
        string memory path = "circuits/build/test_proof.json";
        if (vm.exists(path)) {
            string memory json = vm.readFile(path);
            uint256[] memory pA_raw = vm.parseJsonUintArray(json, ".pA");
            uint256[2] memory pA = [pA_raw[0], pA_raw[1]];

            uint256[] memory pB_0 = vm.parseJsonUintArray(json, ".pB[0]");
            uint256[] memory pB_1 = vm.parseJsonUintArray(json, ".pB[1]");
            uint256[2][2] memory pB = [
                [pB_0[0], pB_0[1]],
                [pB_1[0], pB_1[1]]
            ];

            uint256[] memory pC_raw = vm.parseJsonUintArray(json, ".pC");
            uint256[2] memory pC = [pC_raw[0], pC_raw[1]];

            return abi.encode(pA, pB, pC);
        }

        // Fallback vector, used only when `circuits/build/` has not been
        // generated locally. It is tied to the exact committed
        // `src/verifier/Groth16Verifier.sol` and must be refreshed whenever
        // that file is.
        //
        // `make circuits` is NOT reproducible: `snarkjs zkey contribute` mixes
        // OS randomness into the beacon entropy, so every run produces a
        // different zkey, a different verifier, and a different valid proof —
        // even with compile.sh's fixed BEACON_ENTROPY default. So a rebuild
        // invalidates these numbers, and this path then fails with
        // `InvalidProof` while the artifact-reading path above still passes.
        // If that happens, copy the new values out of
        // `circuits/build/test_proof.json` in the same commit as the
        // regenerated verifier. CI never takes this path — it downloads the
        // freshly built artifacts.
        uint256[2] memory defaultPA = [
            8203646409319772284249272455886631921093597385590529911792735800562458972525,
            2330434065741789284133268057238825017408183091699151738770123221894839700457
        ];

        uint256[2][2] memory defaultPB = [
            [
                15752310160805014795322520071467998124594999371793290957119635034370100479793,
                407827870119593822136222241226999367268666488794854853110683130039816793559
            ],
            [
                20724630947534647524449479543782734951107558499044951121496379942790734133401,
                1147920293371134442638807320180490719762093217741098336474591924227272801687
            ]
        ];

        uint256[2] memory defaultPC = [
            uint256(46193856331985292140779994741637914040125893580633005075158636076966369415),
            uint256(6210719899536482837360687021892992532133040527002656257495925354360146592987)
        ];

        return abi.encode(defaultPA, defaultPB, defaultPC);
    }

    function _createRealPoll() internal {
        voting.createPoll(_getMerkleRoot(), 3, block.timestamp + 1 days, "ipfs://real_poll");
    }

    // =========================================================================
    // Real Groth16 Proof Verification — Happy Path
    // =========================================================================
    function test_RealProof_CastVote_Success() public {
        _createRealPoll();
        bytes32 nullifier = _getNullifierHash();
        uint256 option = _getVoteOption();

        voting.castVote(VOTE_ID, _realProof(), nullifier, option);

        assertTrue(voting.hasVoted(VOTE_ID, nullifier));
        assertEq(voting.getOptionTally(VOTE_ID, option), 1);
    }

    // =========================================================================
    // Error Paths & Attack Vectors
    // =========================================================================
    function test_RevertIf_RealProof_TamperedPointA() public {
        _createRealPoll();
        bytes32 nullifier = _getNullifierHash();

        bytes memory proof = _realProof();
        (uint256[2] memory pA, uint256[2][2] memory pB, uint256[2] memory pC) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));

        pA[0] = uint256(12345);
        pA[1] = uint256(67890);
        bytes memory badProof = abi.encode(pA, pB, pC);

        vm.expectRevert(VotingManager.InvalidProof.selector);
        voting.castVote(VOTE_ID, badProof, nullifier, _getVoteOption());
    }

    function test_RevertIf_RealProof_MismatchedNullifier() public {
        _createRealPoll();

        bytes32 wrongNullifier = bytes32(uint256(0xDEADBEEF));

        vm.expectRevert(VotingManager.InvalidProof.selector);
        voting.castVote(VOTE_ID, _realProof(), wrongNullifier, _getVoteOption());
    }

    /// @notice REGRESSION: a valid proof replayed with a different
    ///         `voteOption` must be rejected.
    ///
    /// @dev This is the test for the ballot-malleability bug. `voteOption`
    ///      used to be an unauthenticated calldata argument that no proof
    ///      committed to. Because `castVote` is permissionless and proofs are
    ///      visible in the mempool, ANY observer could take a pending
    ///      (proof, nullifier) pair, resubmit it with a different option at a
    ///      higher gas price, consume the nullifier, and leave the real
    ///      voter's transaction reverting with `AlreadyVoted` — flipping
    ///      someone else's vote and griefing them at the same time. The same
    ///      rewrite was available to the relayer silently.
    ///
    ///      `voteOption` is now the 4th public signal, so the Groth16 pairing
    ///      check covers it and the attack becomes an `InvalidProof` revert.
    function test_RevertIf_RealProof_RebindsVoteOption() public {
        _createRealPoll();
        bytes32 nullifier = _getNullifierHash();
        uint256 provedOption = _getVoteOption();

        // Pick a different, still in-range option so we get past the
        // `InvalidVoteOption` bound check and actually reach verification —
        // otherwise this would pass for the wrong reason. The poll is created
        // with 3 options (0, 1, 2).
        uint256 attackerOption = provedOption == 0 ? 1 : 0;
        assertTrue(attackerOption != provedOption, "attacker must pick a different option");
        assertTrue(attackerOption < 3, "attacker option must be in range for this poll");

        // Byte-identical proof, byte-identical nullifier, one flipped option.
        vm.expectRevert(VotingManager.InvalidProof.selector);
        voting.castVote(VOTE_ID, _realProof(), nullifier, attackerOption);

        // The griefing half of the attack is dead too: the nullifier was never
        // consumed, so the honest voter can still cast their real ballot.
        assertFalse(voting.hasVoted(VOTE_ID, nullifier));
        voting.castVote(VOTE_ID, _realProof(), nullifier, provedOption);
        assertTrue(voting.hasVoted(VOTE_ID, nullifier));
        assertEq(voting.getOptionTally(VOTE_ID, provedOption), 1);
        assertEq(voting.getOptionTally(VOTE_ID, attackerOption), 0);
    }

    /// @notice A front-runner submitting a different option from a DIFFERENT
    ///         address is equally powerless — the proof, not the sender, is
    ///         what authorises the ballot.
    function test_RevertIf_RealProof_RebindsVoteOption_FromAttackerAddress() public {
        _createRealPoll();
        bytes32 nullifier = _getNullifierHash();
        uint256 provedOption = _getVoteOption();
        uint256 attackerOption = provedOption == 0 ? 1 : 0;

        vm.prank(address(0xBAD));
        vm.expectRevert(VotingManager.InvalidProof.selector);
        voting.castVote(VOTE_ID, _realProof(), nullifier, attackerOption);

        assertFalse(voting.hasVoted(VOTE_ID, nullifier));
    }

    function test_RevertIf_RealProof_CrossPollReplay() public {
        _createRealPoll();
        bytes32 merkleRoot = _getMerkleRoot();
        bytes32 nullifier = _getNullifierHash();

        // Create a second poll with the same Merkle root.
        uint256 poll2 = voting.createPoll(merkleRoot, 3, block.timestamp + 1 days, "ipfs://poll2");
        assertEq(poll2, 2);

        // Try using Poll 1's proof on Poll 2.
        // It must revert because the proof was generated for voteId = 1, not voteId = 2.
        vm.expectRevert(VotingManager.InvalidProof.selector);
        voting.castVote(poll2, _realProof(), nullifier, _getVoteOption());
    }

    function test_RevertIf_RealProof_DoubleVoteReplay() public {
        _createRealPoll();
        bytes32 nullifier = _getNullifierHash();
        uint256 option = _getVoteOption();

        voting.castVote(VOTE_ID, _realProof(), nullifier, option);

        // Second submission with exact same valid proof + nullifier
        vm.expectRevert(abi.encodeWithSelector(VotingManager.AlreadyVoted.selector, nullifier));
        voting.castVote(VOTE_ID, _realProof(), nullifier, option);
    }
}
