// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {VotingManager} from "../src/VotingManager.sol";
import {IVotingManager} from "../src/IVotingManager.sol";
import {MockVerifier} from "./mocks/MockVerifier.sol";

/// @title VotingManagerTest
/// @notice Exercises the non-cryptographic control flow of `VotingManager`:
///         access control, poll lifecycle, option bounds, nullifier dedup and
///         the invalid-proof path. The pairing math itself is delegated to
///         `MockVerifier`, so these tests are fast and hermetic.
contract VotingManagerTest is Test {
    VotingManager internal voting;
    MockVerifier internal mockVerifier;

    address internal owner = address(this);
    address internal voter = address(0xBEEF);

    // A throwaway root — the mock verifier doesn't inspect it, so any bytes32
    // will do. (Real flows pass the Poseidon Merkle root from gen_input.js.)
    bytes32 internal constant ROOT = bytes32(uint256(0xABCDEF));

    uint256 internal constant POLL_ID = 1;
    uint256 internal constant NUM_OPTIONS = 3;
    uint256 internal constant OPTION = 1;
    bytes32 internal constant NULLIFIER = bytes32(uint256(0x1234));

    function setUp() public {
        mockVerifier = new MockVerifier();
        voting = new VotingManager(address(mockVerifier));
    }

    // Helper: build a proof blob whose shape `castVote` can abi.decode.
    // The values are nonsensical — the mock ignores them — but the bytes
    // layout must be valid abi.encode(pA, pB, pC).
    function _dummyProof() internal pure returns (bytes memory) {
        uint256[2] memory pA = [uint256(1), uint256(1)];
        uint256[2][2] memory pB = [[uint256(1), uint256(1)], [uint256(1), uint256(1)]];
        uint256[2] memory pC = [uint256(1), uint256(1)];
        return abi.encode(pA, pB, pC);
    }

    function _createPoll() internal returns (uint256 pollId) {
        pollId = voting.createPoll(ROOT, NUM_OPTIONS, block.timestamp + 1 days, "ipfs://poll1");
        assertEq(pollId, POLL_ID);
    }

    // =========================================================================
    // Deployment
    // =========================================================================
    function test_RevertIf_DeployWithZeroVerifier() public {
        vm.expectRevert(VotingManager.ZeroVerifier.selector);
        new VotingManager(address(0));
    }

    function test_InitialState() public view {
        assertEq(address(voting.verifier()), address(mockVerifier));
        assertEq(voting.owner(), owner);
        assertEq(voting.nextPollId(), 1);
    }

    // =========================================================================
    // createPoll
    // =========================================================================
    function test_CreatePoll_EmitsAndStores() public {
        vm.expectEmit(true, true, false, true);
        emit IVotingManager.PollCreated(POLL_ID, ROOT, block.timestamp + 1 days, NUM_OPTIONS, "ipfs://poll1");
        uint256 id = voting.createPoll(ROOT, NUM_OPTIONS, block.timestamp + 1 days, "ipfs://poll1");
        assertEq(id, POLL_ID);
        assertEq(voting.nextPollId(), POLL_ID + 1);

        (bytes32 root, uint256 deadline, uint256 numOpts, uint256 total, bool active) =
            voting.getPoll(POLL_ID);
        assertEq(root, ROOT);
        assertEq(deadline, block.timestamp + 1 days);
        assertEq(numOpts, NUM_OPTIONS);
        assertEq(total, 0);
        assertTrue(active);
    }

    function test_RevertIf_CreatePoll_NotOwner() public {
        vm.prank(voter);
        vm.expectRevert(VotingManager.Unauthorized.selector);
        voting.createPoll(ROOT, NUM_OPTIONS, block.timestamp + 1 days, "x");
    }

    function test_RevertIf_CreatePoll_PastDeadline() public {
        vm.expectRevert(VotingManager.InvalidDeadline.selector);
        voting.createPoll(ROOT, NUM_OPTIONS, block.timestamp - 1, "x");
    }

    function test_RevertIf_CreatePoll_TooFewOptions() public {
        vm.expectRevert(VotingManager.InvalidNumOptions.selector);
        voting.createPoll(ROOT, 1, block.timestamp + 1 days, "x");
    }

    // =========================================================================
    // castVote — happy path
    // =========================================================================
    function test_CastVote_HappyPath() public {
        _createPoll();

        vm.expectEmit(true, true, false, true);
        emit IVotingManager.VoteCast(POLL_ID, NULLIFIER, OPTION);
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, OPTION);

        assertTrue(voting.hasVoted(POLL_ID, NULLIFIER));
        assertEq(voting.getOptionTally(POLL_ID, OPTION), 1);
        (, , , uint256 total, ) = voting.getPoll(POLL_ID);
        assertEq(total, 1);
    }

    // =========================================================================
    // castVote — error paths
    // =========================================================================
    function test_RevertIf_CastVote_PollMissing() public {
        vm.expectRevert(abi.encodeWithSelector(VotingManager.PollDoesNotExist.selector, 999));
        voting.castVote(999, _dummyProof(), NULLIFIER, OPTION);
    }

    function test_RevertIf_CastVote_PollClosed() public {
        _createPoll();
        voting.closePoll(POLL_ID);
        vm.expectRevert(abi.encodeWithSelector(VotingManager.PollNotActive.selector, POLL_ID));
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, OPTION);
    }

    function test_RevertIf_CastVote_PollEnded() public {
        _createPoll();
        // Jump past the deadline.
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(abi.encodeWithSelector(VotingManager.PollEnded.selector, POLL_ID));
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, OPTION);
    }

    function test_RevertIf_CastVote_BadOption_TooLow() public {
        _createPoll();
        vm.expectRevert(abi.encodeWithSelector(VotingManager.InvalidVoteOption.selector, NUM_OPTIONS));
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, NUM_OPTIONS);
    }

    function test_RevertIf_CastVote_InvalidProof() public {
        _createPoll();
        mockVerifier.setShouldAccept(false);
        vm.expectRevert(VotingManager.InvalidProof.selector);
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, OPTION);
    }

    function test_RevertIf_CastVote_DoubleVote() public {
        _createPoll();
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, OPTION);

        // Same nullifier again, even with a (mocked-valid) fresh proof.
        vm.expectRevert(abi.encodeWithSelector(VotingManager.AlreadyVoted.selector, NULLIFIER));
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, OPTION);
    }

    function test_RevertIf_CastVote_MalformedProof() public {
        _createPoll();
        // Too-short blob: abi.decode will fail. Solidity bubbles that up as a
        // generic revert — we just assert the call reverts.
        vm.expectRevert();
        voting.castVote(POLL_ID, bytes("nope"), NULLIFIER, OPTION);
    }

    // =========================================================================
    // Independent nullifiers across polls
    // =========================================================================
    function test_DistinctPolls_AcceptSameNullifierShapeIndependently() public {
        // Two polls, same bytes32 nullifier value, both should be allowed
        // (in reality the nullifier depends on pollId so values differ; this
        // just proves the dedup is per-poll, not global).
        uint256 a = voting.createPoll(ROOT, NUM_OPTIONS, block.timestamp + 1 days, "a");
        uint256 b = voting.createPoll(ROOT, NUM_OPTIONS, block.timestamp + 1 days, "b");

        voting.castVote(a, _dummyProof(), NULLIFIER, OPTION);
        // No revert expected — different pollId key.
        voting.castVote(b, _dummyProof(), NULLIFIER, OPTION);

        assertTrue(voting.hasVoted(a, NULLIFIER));
        assertTrue(voting.hasVoted(b, NULLIFIER));
    }

    // =========================================================================
    // Admin
    // =========================================================================
    function test_ClosePoll_Emits() public {
        _createPoll();
        vm.expectEmit(true, false, false, true);
        emit IVotingManager.PollClosed(POLL_ID);
        voting.closePoll(POLL_ID);
        (, , , , bool active) = voting.getPoll(POLL_ID);
        assertFalse(active);
    }

    function test_TransferOwnership() public {
        voting.transferOwnership(voter);
        assertEq(voting.owner(), voter);
    }

    function test_RevertIf_TransferOwnership_ToZero() public {
        vm.expectRevert(VotingManager.Unauthorized.selector);
        voting.transferOwnership(address(0));
    }
}
