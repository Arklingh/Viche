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

    // Real public signals from proof-demo (gen_proof.js)
    uint256 internal constant VOTE_ID = 1;
    bytes32 internal constant MERKLE_ROOT = bytes32(uint256(18142334754527230829434618760706122867182291645357706712475860565891430848844));
    bytes32 internal constant NULLIFIER_HASH = bytes32(uint256(4187152743772995393318417670842768441279259923326005547157850571084256757975));

    function setUp() public {
        realVerifier = new Groth16Verifier();
        voting = new VotingManager(address(realVerifier));
    }

    /// @dev Helper to construct the exact 256-byte `abi.encode(pA, pB, pC)` payload
    ///      from the real Groth16 proof points.
    function _realProof() internal pure returns (bytes memory) {
        uint256[2] memory pA = [
            7506704964354824737496777427316488688464786563807530666304862735152496131180,
            11852427395163530980752069446199190315793722354028449112327427837006693445561
        ];

        // snarkjs stores G2 as [ [X.c0, X.c1], [Y.c0, Y.c1] ].
        // Solidity verifier expects [ [X.c1, X.c0], [Y.c1, Y.c0] ].
        uint256[2][2] memory pB = [
            [
                16473857080351023299726316830250981479063482619888672866254928666117979087462,
                3334183968173742828419858244539624005923856678218719623523500412242139509634
            ],
            [
                2630219384070283677202667216630781540776557037023146408117005869961795656082,
                1014135746170549120065002289070128567304912397101534196740845911834003975055
            ]
        ];

        uint256[2] memory pC = [
            9357618835125017893204880742813946928700651730610843650383432989189866152415,
            3006735565490607570718679026951413737279870028629696639331723704985428721918
        ];

        return abi.encode(pA, pB, pC);
    }

    function _createRealPoll() internal {
        voting.createPoll(MERKLE_ROOT, 3, block.timestamp + 1 days, "ipfs://real_poll");
    }

    // =========================================================================
    // Real Groth16 Proof Verification — Happy Path
    // =========================================================================
    function test_RealProof_CastVote_Success() public {
        _createRealPoll();

        voting.castVote(VOTE_ID, _realProof(), NULLIFIER_HASH, 1);

        assertTrue(voting.hasVoted(VOTE_ID, NULLIFIER_HASH));
        assertEq(voting.getOptionTally(VOTE_ID, 1), 1);
    }

    // =========================================================================
    // Error Paths & Attack Vectors
    // =========================================================================
    function test_RevertIf_RealProof_TamperedPointA() public {
        _createRealPoll();

        uint256[2] memory badPA = [uint256(12345), uint256(67890)];
        uint256[2][2] memory pB = [
            [
                16473857080351023299726316830250981479063482619888672866254928666117979087462,
                3334183968173742828419858244539624005923856678218719623523500412242139509634
            ],
            [
                2630219384070283677202667216630781540776557037023146408117005869961795656082,
                1014135746170549120065002289070128567304912397101534196740845911834003975055
            ]
        ];
        uint256[2] memory pC = [
            9357618835125017893204880742813946928700651730610843650383432989189866152415,
            3006735565490607570718679026951413737279870028629696639331723704985428721918
        ];
        bytes memory badProof = abi.encode(badPA, pB, pC);

        vm.expectRevert(VotingManager.InvalidProof.selector);
        voting.castVote(VOTE_ID, badProof, NULLIFIER_HASH, 1);
    }

    function test_RevertIf_RealProof_MismatchedNullifier() public {
        _createRealPoll();

        bytes32 wrongNullifier = bytes32(uint256(0xDEADBEEF));

        vm.expectRevert(VotingManager.InvalidProof.selector);
        voting.castVote(VOTE_ID, _realProof(), wrongNullifier, 1);
    }

    function test_RevertIf_RealProof_CrossPollReplay() public {
        _createRealPoll();
        // Create a second poll with the same Merkle root.
        uint256 poll2 = voting.createPoll(MERKLE_ROOT, 3, block.timestamp + 1 days, "ipfs://poll2");
        assertEq(poll2, 2);

        // Try using Poll 1's proof on Poll 2.
        // It must revert because the proof was generated for voteId = 1, not voteId = 2.
        vm.expectRevert(VotingManager.InvalidProof.selector);
        voting.castVote(poll2, _realProof(), NULLIFIER_HASH, 1);
    }

    function test_RevertIf_RealProof_DoubleVoteReplay() public {
        _createRealPoll();

        voting.castVote(VOTE_ID, _realProof(), NULLIFIER_HASH, 1);

        // Second submission with exact same valid proof + nullifier
        vm.expectRevert(abi.encodeWithSelector(VotingManager.AlreadyVoted.selector, NULLIFIER_HASH));
        voting.castVote(VOTE_ID, _realProof(), NULLIFIER_HASH, 1);
    }
}
