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
    // Local event declarations for expectEmit. Solidity 0.8.20 does not
    // support `ContractName.EventName` references, so we re-declare the
    // events here; matching is done by selector (identical signatures).
    event PollCreated(uint256 indexed pollId, bytes32 indexed merkleRoot, uint256 deadline, uint256 numOptions, string metadataUri);
    event PollClosed(uint256 indexed pollId);
    event PollCancelled(uint256 indexed pollId, string reason);
    event PollVoid(uint256 indexed pollId, uint256 totalVotes, string reason);
    event VoteCast(uint256 indexed pollId, bytes32 indexed nullifierHash, uint256 voteOption);

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
        emit PollCreated(POLL_ID, ROOT, block.timestamp + 1 days, NUM_OPTIONS, "ipfs://poll1");
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
        emit VoteCast(POLL_ID, NULLIFIER, OPTION);
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

    /// @dev A poll can no longer be closed before its deadline, so the way to
    ///      reach "not accepting votes while still inside the voting window"
    ///      is now to cancel it (no votes cast) or void it. Both must stop
    ///      `castVote` for the same reason the old early close did.
    function test_RevertIf_CastVote_PollCancelled() public {
        _createPoll();
        voting.cancelPoll(POLL_ID, "wrong merkle root");
        vm.expectRevert(abi.encodeWithSelector(VotingManager.PollNotActive.selector, POLL_ID));
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, OPTION);
    }

    function test_RevertIf_CastVote_PollVoided() public {
        _createPoll();
        voting.voidPoll(POLL_ID, "whitelist compromised");
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
    function test_ClosePoll_AfterDeadline_Emits() public {
        _createPoll();
        vm.warp(block.timestamp + 2 days);
        vm.expectEmit(true, false, false, true);
        emit PollClosed(POLL_ID);
        voting.closePoll(POLL_ID);
        (, , , , bool active) = voting.getPoll(POLL_ID);
        assertFalse(active);
        assertEq(uint256(voting.getPollStatus(POLL_ID)), uint256(VotingManager.PollStatus.Closed));
    }

    // ---- Close-time integrity ------------------------------------------
    //
    // The tally is public and updates per vote. If an admin could close at
    // will, they could watch it and freeze the count the moment it favoured
    // them. These tests pin that door shut.

    function test_RevertIf_ClosePoll_BeforeDeadline() public {
        uint256 deadline = block.timestamp + 1 days;
        _createPoll();
        vm.expectRevert(
            abi.encodeWithSelector(VotingManager.PollStillOpen.selector, POLL_ID, deadline)
        );
        voting.closePoll(POLL_ID);
    }

    function test_RevertIf_ClosePoll_Twice() public {
        _createPoll();
        vm.warp(block.timestamp + 2 days);
        voting.closePoll(POLL_ID);
        vm.expectRevert(abi.encodeWithSelector(VotingManager.PollNotOpen.selector, POLL_ID));
        voting.closePoll(POLL_ID);
    }

    // ---- cancelPoll: only before anyone has voted ------------------------

    function test_CancelPoll_BeforeAnyVote() public {
        _createPoll();
        vm.expectEmit(true, false, false, true);
        emit PollCancelled(POLL_ID, "wrong root");
        voting.cancelPoll(POLL_ID, "wrong root");
        assertEq(
            uint256(voting.getPollStatus(POLL_ID)), uint256(VotingManager.PollStatus.Cancelled)
        );
    }

    function test_RevertIf_CancelPoll_AfterAVoteLands() public {
        _createPoll();
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, OPTION);
        vm.expectRevert(abi.encodeWithSelector(VotingManager.PollHasVotes.selector, POLL_ID, 1));
        voting.cancelPoll(POLL_ID, "too late");
    }

    function test_RevertIf_CancelPoll_NotOwner() public {
        _createPoll();
        vm.prank(voter);
        vm.expectRevert(VotingManager.Unauthorized.selector);
        voting.cancelPoll(POLL_ID, "nope");
    }

    // ---- voidPoll: discards rather than freezes ---------------------------

    /// @dev The core anti-abuse property. An admin who stops a poll mid-vote
    ///      must not be able to keep the favourable partial count: the tally
    ///      has to become unreadable, so voiding can only ever yield "no
    ///      result", never "the result I was winning".
    function test_VoidPoll_MakesTheTallyUnreadable() public {
        _createPoll();
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, OPTION);
        assertEq(voting.getOptionTally(POLL_ID, OPTION), 1);

        voting.voidPoll(POLL_ID, "whitelist compromised");

        vm.expectRevert(abi.encodeWithSelector(VotingManager.PollVoided.selector, POLL_ID));
        voting.getOptionTally(POLL_ID, OPTION);
    }

    function test_VoidPoll_EmitsVoteCountForAudit() public {
        _createPoll();
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, OPTION);
        vm.expectEmit(true, false, false, true);
        emit PollVoid(POLL_ID, 1, "circuit bug");
        voting.voidPoll(POLL_ID, "circuit bug");
    }

    function test_RevertIf_VoidPoll_NotOwner() public {
        _createPoll();
        vm.prank(voter);
        vm.expectRevert(VotingManager.Unauthorized.selector);
        voting.voidPoll(POLL_ID, "nope");
    }

    // ---- Two-step ownership ----------------------------------------------

    function test_TransferOwnership_IsTwoStep() public {
        voting.transferOwnership(voter);

        // Step one proposes only — control has NOT moved yet.
        assertEq(voting.owner(), address(this));
        assertEq(voting.pendingOwner(), voter);

        vm.prank(voter);
        voting.acceptOwnership();

        assertEq(voting.owner(), voter);
        assertEq(voting.pendingOwner(), address(0));
    }

    /// @dev The failure a two-step handover exists to prevent: a transfer to
    ///      an address that cannot sign would otherwise brick administration
    ///      permanently, since there is no other privileged role.
    function test_PendingOwnerThatNeverAccepts_LeavesControlIntact() public {
        voting.transferOwnership(address(0xdead));
        assertEq(voting.owner(), address(this));

        // The original owner still governs, and can still run polls.
        _createPoll();
        assertEq(uint256(voting.getPollStatus(POLL_ID)), uint256(VotingManager.PollStatus.Open));
    }

    function test_RevertIf_AcceptOwnership_FromWrongAddress() public {
        voting.transferOwnership(voter);
        vm.prank(address(0xbad));
        vm.expectRevert(VotingManager.NotPendingOwner.selector);
        voting.acceptOwnership();
    }

    function test_RevertIf_AcceptOwnership_WithNoTransferPending() public {
        vm.prank(voter);
        vm.expectRevert(VotingManager.NotPendingOwner.selector);
        voting.acceptOwnership();
    }

    function test_CancelOwnershipTransfer() public {
        voting.transferOwnership(voter);
        voting.cancelOwnershipTransfer();
        assertEq(voting.pendingOwner(), address(0));

        // The withdrawn proposal must not still be acceptable.
        vm.prank(voter);
        vm.expectRevert(VotingManager.NotPendingOwner.selector);
        voting.acceptOwnership();
    }

    function test_RevertIf_CancelOwnershipTransfer_WithNothingPending() public {
        vm.expectRevert(VotingManager.NoPendingOwner.selector);
        voting.cancelOwnershipTransfer();
    }

    function test_ProposingAgainReplacesThePriorPendingOwner() public {
        voting.transferOwnership(voter);
        voting.transferOwnership(address(0xfeed));
        assertEq(voting.pendingOwner(), address(0xfeed));

        vm.prank(voter);
        vm.expectRevert(VotingManager.NotPendingOwner.selector);
        voting.acceptOwnership();
    }

    function test_RevertIf_TransferOwnership_ToZero() public {
        vm.expectRevert(VotingManager.Unauthorized.selector);
        voting.transferOwnership(address(0));
    }

    function test_RevertIf_TransferOwnership_NotOwner() public {
        vm.prank(voter);
        vm.expectRevert(VotingManager.Unauthorized.selector);
        voting.transferOwnership(voter);
    }

    // =====================================================================
    // Fuzz tests
    //
    // These target the properties where an off-by-one or a missing bound is
    // easy to write and hard to spot by reading: access control, option
    // bounds, and the two close-time guards.
    // =====================================================================

    /// @dev Every admin entry point must reject every address that is not the
    ///      owner — not just the one `voter` address the unit tests use.
    function testFuzz_OnlyOwnerCanAdminister(address caller) public {
        vm.assume(caller != address(this));
        _createPoll();

        vm.startPrank(caller);
        vm.expectRevert(VotingManager.Unauthorized.selector);
        voting.createPoll(bytes32(uint256(1)), 2, block.timestamp + 1 days, "");
        vm.expectRevert(VotingManager.Unauthorized.selector);
        voting.closePoll(POLL_ID);
        vm.expectRevert(VotingManager.Unauthorized.selector);
        voting.cancelPoll(POLL_ID, "x");
        vm.expectRevert(VotingManager.Unauthorized.selector);
        voting.voidPoll(POLL_ID, "x");
        vm.expectRevert(VotingManager.Unauthorized.selector);
        voting.transferOwnership(caller);
        vm.stopPrank();
    }

    /// @dev Any option index at or above `numOptions` must be rejected. The
    ///      bound is `>=`, which is exactly the kind of comparison that is one
    ///      keystroke from wrong.
    function testFuzz_RejectsOutOfRangeOption(uint256 option) public {
        _createPoll();
        (, , uint256 numOptions, , ) = voting.getPoll(POLL_ID);
        option = bound(option, numOptions, type(uint256).max);

        vm.expectRevert(
            abi.encodeWithSelector(VotingManager.InvalidVoteOption.selector, option)
        );
        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, option);
    }

    /// @dev Any in-range option must be accepted and credited to that option
    ///      alone.
    function testFuzz_AcceptsAnyInRangeOption(uint256 option) public {
        _createPoll();
        (, , uint256 numOptions, , ) = voting.getPoll(POLL_ID);
        option = bound(option, 0, numOptions - 1);

        voting.castVote(POLL_ID, _dummyProof(), NULLIFIER, option);

        assertEq(voting.getOptionTally(POLL_ID, option), 1);
        (, , , uint256 totalVotes, ) = voting.getPoll(POLL_ID);
        assertEq(totalVotes, 1);
    }

    /// @dev No moment before the deadline may permit a close. This is the
    ///      integrity property: an admin must never be able to freeze a tally
    ///      that currently favours them, at any point in the voting window.
    function testFuzz_ClosePollAlwaysRevertsBeforeDeadline(uint256 secondsAhead) public {
        uint256 deadline = block.timestamp + 1 days;
        _createPoll();
        // Anywhere strictly inside the window, including the deadline itself.
        secondsAhead = bound(secondsAhead, 0, deadline - block.timestamp);
        vm.warp(block.timestamp + secondsAhead);

        vm.expectRevert(
            abi.encodeWithSelector(VotingManager.PollStillOpen.selector, POLL_ID, deadline)
        );
        voting.closePoll(POLL_ID);
    }

    /// @dev Ownership must only ever move to the exact pending address.
    function testFuzz_OnlyPendingOwnerCanAccept(address proposed, address caller) public {
        vm.assume(proposed != address(0));
        vm.assume(caller != proposed);

        voting.transferOwnership(proposed);

        vm.prank(caller);
        vm.expectRevert(VotingManager.NotPendingOwner.selector);
        voting.acceptOwnership();

        assertEq(voting.owner(), address(this), "ownership must not have moved");
    }

    /// @dev A poll with any number of votes on it can never be cancelled.
    function testFuzz_CancelRejectedOnceAnyVoteExists(uint8 voteCount) public {
        uint256 n = bound(voteCount, 1, 20);
        _createPoll();
        for (uint256 i = 0; i < n; i++) {
            voting.castVote(POLL_ID, _dummyProof(), keccak256(abi.encode(i)), OPTION);
        }

        vm.expectRevert(abi.encodeWithSelector(VotingManager.PollHasVotes.selector, POLL_ID, n));
        voting.cancelPoll(POLL_ID, "too late");
    }
}
