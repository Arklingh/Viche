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
            12589105823469349683064907521005714504209333153595828501764595466456532402514,
            19962048662089782497115445396859789232526257768572853556324804584954883336591
        ];

        // snarkjs stores G2 as [ [X.c0, X.c1], [Y.c0, Y.c1] ].
        // Solidity verifier expects [ [X.c1, X.c0], [Y.c1, Y.c0] ].
        uint256[2][2] memory pB = [
            [
                5789288541062466527049003890094832981558409669038877230688484010175714529335,
                2471133188116564937373376625192222486399682772814582159851675096123074724249
            ],
            [
                15341713254377565147392765741870035744799452169907896636940888760169917387230,
                18719439880895548378098535883781903647269495986595533327681744178478987907101
            ]
        ];

        uint256[2] memory pC = [
            uint256(92096001134779114346853457083316945457930832444041226063738659253658584785),
            uint256(405256599027472823869381607603642916397613799689972452281955398987014630313)
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
                5789288541062466527049003890094832981558409669038877230688484010175714529335,
                2471133188116564937373376625192222486399682772814582159851675096123074724249
            ],
            [
                15341713254377565147392765741870035744799452169907896636940888760169917387230,
                18719439880895548378098535883781903647269495986595533327681744178478987907101
            ]
        ];
        uint256[2] memory pC = [
            uint256(92096001134779114346853457083316945457930832444041226063738659253658584785),
            uint256(405256599027472823869381607603642916397613799689972452281955398987014630313)
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
