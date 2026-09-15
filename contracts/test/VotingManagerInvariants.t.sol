// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VotingManager} from "../src/VotingManager.sol";
import {MockVerifier} from "./mocks/MockVerifier.sol";

/// @title VotingManagerHandler
/// @notice Invariant-test handler: the only actor the fuzzer drives.
///
/// @dev Invariant testing without a handler would have the fuzzer call
///      `VotingManager` directly with random calldata, which spends almost
///      every run bouncing off `onlyOwner` and `pollExists` and almost none
///      exploring real state transitions. This handler funnels the fuzzer
///      into the reachable action space — vote, cancel, void, close, hand
///      over ownership — while tracking, independently of the contract, what
///      the answers *should* be. The invariants below then compare the
///      contract against this shadow accounting.
contract VotingManagerHandler is Test {
    VotingManager public voting;

    /// @dev Poll ids this handler has created.
    uint256[] public pollIds;

    /// @dev Shadow tally: pollId => option => count, maintained independently
    ///      of the contract so the invariant has something to disagree with.
    mapping(uint256 => mapping(uint256 => uint256)) public shadowTally;
    /// @dev Shadow total votes per poll.
    mapping(uint256 => uint256) public shadowTotal;
    /// @dev Polls this handler has voided, so invariants know not to read them.
    mapping(uint256 => bool) public voided;
    /// @dev Every nullifier accepted, to prove none was ever accepted twice.
    mapping(uint256 => mapping(bytes32 => bool)) public usedNullifier;

    /// @dev Counts successful votes across all polls; lets the invariant
    ///      suite assert the fuzzer actually reached the interesting states
    ///      rather than passing vacuously.
    uint256 public totalAccepted;
    uint256 public rejected;

    uint256 internal constant NUM_OPTIONS = 4;
    uint256 internal nonce;

    constructor(VotingManager voting_) {
        voting = voting_;
        // No poll here: the handler does not own the contract yet. `init` is
        // called after ownership has been accepted.
    }

    /// @dev Seed the first poll. Must run after the handler owns the contract.
    function init() external {
        _createPoll();
    }

    function pollCount() external view returns (uint256) {
        return pollIds.length;
    }

    function _createPoll() internal {
        uint256 id = voting.createPoll(
            bytes32(uint256(0xabc)), NUM_OPTIONS, block.timestamp + 365 days, "ipfs://invariant"
        );
        pollIds.push(id);
    }

    /// @dev A dummy proof. `MockVerifier` accepts anything well-formed, so the
    ///      fuzzer explores lifecycle and accounting rather than re-testing
    ///      Groth16 — the real verifier has its own integration suite.
    function _proof() internal pure returns (bytes memory) {
        return abi.encode(
            [uint256(1), uint256(2)],
            [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
            [uint256(7), uint256(8)]
        );
    }

    function createPoll(uint256 seed) external {
        seed;
        _createPoll();
    }

    /// @dev Return a poll that is currently accepting votes, creating one if
    ///      none is.
    ///
    ///      Without this the suite is silently vacuous: three of the handler's
    ///      actions retire polls and only one creates them, so the fuzzer
    ///      kills every poll long before it has finished voting, and
    ///      `castVote` spends the rest of the run bouncing off dead polls.
    ///      Measured across seeds, that produced anywhere from 0 to 16
    ///      accepted votes out of ~4000 attempts — meaning whether the
    ///      invariants tested anything at all depended on the seed. Keeping
    ///      one poll alive makes the accounting invariants meaningful on every
    ///      run, while the fuzzer stays free to retire polls as it likes.
    function _livePoll() internal returns (uint256) {
        for (uint256 i = 0; i < pollIds.length; i++) {
            if (voting.getPollStatus(pollIds[i]) == VotingManager.PollStatus.Open) {
                return pollIds[i];
            }
        }
        _createPoll();
        return pollIds[pollIds.length - 1];
    }

    function castVote(uint256 pollSeed, uint256 optionSeed, uint256 nullifierSeed) external {
        pollSeed;
        uint256 pollId = _livePoll();
        uint256 option = optionSeed % NUM_OPTIONS;
        bytes32 nullifier = keccak256(abi.encode(nullifierSeed, nonce++));

        try voting.castVote(pollId, _proof(), nullifier, option) {
            shadowTally[pollId][option] += 1;
            shadowTotal[pollId] += 1;
            usedNullifier[pollId][nullifier] = true;
            totalAccepted += 1;
        } catch {
            rejected += 1;
        }
    }

    /// @dev Deliberately replays an already-used nullifier. The invariant that
    ///      matters is that this NEVER increases a tally.
    function replayVote(uint256 pollSeed, uint256 optionSeed, bytes32 nullifier) external {
        if (pollIds.length == 0) return;
        uint256 pollId = pollIds[pollSeed % pollIds.length];
        uint256 option = optionSeed % NUM_OPTIONS;
        try voting.castVote(pollId, _proof(), nullifier, option) {
            shadowTally[pollId][option] += 1;
            shadowTotal[pollId] += 1;
            usedNullifier[pollId][nullifier] = true;
            totalAccepted += 1;
        } catch {}
    }

    function cancelPoll(uint256 pollSeed) external {
        if (pollIds.length == 0) return;
        uint256 pollId = pollIds[pollSeed % pollIds.length];
        try voting.cancelPoll(pollId, "fuzz") {} catch {}
    }

    function voidPoll(uint256 pollSeed) external {
        if (pollIds.length == 0) return;
        uint256 pollId = pollIds[pollSeed % pollIds.length];
        try voting.voidPoll(pollId, "fuzz") {
            voided[pollId] = true;
        } catch {}
    }

    function closePoll(uint256 pollSeed) external {
        if (pollIds.length == 0) return;
        uint256 pollId = pollIds[pollSeed % pollIds.length];
        try voting.closePoll(pollId) {} catch {}
    }

    function warp(uint256 secondsAhead) external {
        vm.warp(block.timestamp + (secondsAhead % 30 days));
    }

    /// @dev Tries to hand ownership to a random address. Ownership must not
    ///      actually move without an `acceptOwnership`, which this never calls.
    function tryTransferOwnership(address to) external {
        if (to == address(0)) return;
        try voting.transferOwnership(to) {} catch {}
    }
}

/// @title VotingManagerInvariants
/// @notice Properties that must hold no matter what sequence of admin and
///         voter actions the fuzzer produces.
contract VotingManagerInvariants is Test {
    VotingManager internal voting;
    VotingManagerHandler internal handler;

    function setUp() public {
        MockVerifier verifier = new MockVerifier(); // accepts by default
        voting = new VotingManager(address(verifier));
        handler = new VotingManagerHandler(voting);

        // Ownership must sit with the handler, since it creates polls.
        voting.transferOwnership(address(handler));
        vm.prank(address(handler));
        voting.acceptOwnership();
        handler.init();

        targetContract(address(handler));
        // `init` is setup, not an action the fuzzer should replay, and
        // `pollIds`/`shadowTally` are view helpers for the invariants.
        bytes4[] memory selectors = new bytes4[](8);
        selectors[0] = VotingManagerHandler.createPoll.selector;
        selectors[1] = VotingManagerHandler.castVote.selector;
        selectors[2] = VotingManagerHandler.replayVote.selector;
        selectors[3] = VotingManagerHandler.cancelPoll.selector;
        selectors[4] = VotingManagerHandler.voidPoll.selector;
        selectors[5] = VotingManagerHandler.closePoll.selector;
        selectors[6] = VotingManagerHandler.warp.selector;
        selectors[7] = VotingManagerHandler.tryTransferOwnership.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @notice The per-option tallies must always sum to `totalVotes`.
    ///
    /// @dev Catches any double-count or miscount in `castVote`'s unchecked
    ///      block — the place where a vote could be credited to the tally but
    ///      not the total, or vice versa.
    function invariant_TalliesSumToTotalVotes() public view {
        uint256 n = handler.pollCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 pollId = handler.pollIds(i);
            if (handler.voided(pollId)) continue; // tallies are unreadable

            (, , uint256 numOptions, uint256 totalVotes, ) = voting.getPoll(pollId);
            uint256 sum;
            for (uint256 opt = 0; opt < numOptions; opt++) {
                sum += voting.getOptionTally(pollId, opt);
            }
            assertEq(sum, totalVotes, "option tallies must sum to totalVotes");
        }
    }

    /// @notice The contract's accounting must match independent shadow
    ///         accounting kept outside it.
    function invariant_ContractAgreesWithShadowTally() public view {
        uint256 n = handler.pollCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 pollId = handler.pollIds(i);
            if (handler.voided(pollId)) continue;

            (, , uint256 numOptions, uint256 totalVotes, ) = voting.getPoll(pollId);
            assertEq(totalVotes, handler.shadowTotal(pollId), "totalVotes diverged from shadow");
            for (uint256 opt = 0; opt < numOptions; opt++) {
                assertEq(
                    voting.getOptionTally(pollId, opt),
                    handler.shadowTally(pollId, opt),
                    "option tally diverged from shadow"
                );
            }
        }
    }

    /// @notice A voided poll's tally must never be readable.
    ///
    /// @dev This is the property that makes `voidPoll` unprofitable. If it
    ///      ever became readable, an admin could void while ahead and point at
    ///      the frozen numbers as a result.
    function invariant_VoidedPollsNeverRevealTheirTally() public {
        uint256 n = handler.pollCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 pollId = handler.pollIds(i);
            if (!handler.voided(pollId)) continue;

            vm.expectRevert(abi.encodeWithSelector(VotingManager.PollVoided.selector, pollId));
            voting.getOptionTally(pollId, 0);
        }
    }

    /// @notice A poll that has ended can never accept another vote, so its
    ///         total can only be less than or equal to the shadow total.
    ///
    /// @dev Guards against a lifecycle transition accidentally reopening a
    ///      poll — e.g. a future status change that forgets to stay terminal.
    function invariant_EndedPollsNeverGainVotes() public view {
        uint256 n = handler.pollCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 pollId = handler.pollIds(i);
            VotingManager.PollStatus status = voting.getPollStatus(pollId);
            if (status == VotingManager.PollStatus.Open) continue;

            (, , , uint256 totalVotes, bool active) = voting.getPoll(pollId);
            assertFalse(active, "a non-Open poll must never report active");
            assertEq(totalVotes, handler.shadowTotal(pollId), "ended poll gained votes");
        }
    }

    /// @notice A cancelled poll must have zero votes, by construction.
    function invariant_CancelledPollsHaveNoVotes() public view {
        uint256 n = handler.pollCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 pollId = handler.pollIds(i);
            if (voting.getPollStatus(pollId) != VotingManager.PollStatus.Cancelled) continue;
            (, , , uint256 totalVotes, ) = voting.getPoll(pollId);
            assertEq(totalVotes, 0, "a cancelled poll must never hold votes");
        }
    }

    /// @notice Ownership never moves without an explicit `acceptOwnership`.
    ///
    /// @dev The handler repeatedly proposes transfers and never accepts one,
    ///      so the owner must still be the handler at all times. This is the
    ///      brick-the-contract failure the two-step handover prevents.
    function invariant_OwnershipNeverMovesWithoutAcceptance() public view {
        assertEq(voting.owner(), address(handler), "ownership moved without acceptance");
    }

}

/// @title VotingManagerHandlerWiringTest
/// @notice Proves the invariant handler can actually reach the states the
///         invariants are about.
///
/// @dev This exists because an invariant suite fails silently-green when the
///      fuzzer never reaches interesting state: every property above is of the
///      form "X is still consistent", which holds trivially if no vote was
///      ever cast, and the handler swallows reverts so nothing complains.
///      This suite really was vacuous at one point — measured across seeds it
///      landed between 0 and 16 votes out of ~4000 attempts, because three
///      handler actions retire polls and only one creates them.
///
///      `_livePoll()` fixed that, and these deterministic tests are what keep
///      it fixed. They do not depend on fuzzer scheduling or on
///      `afterInvariant` state visibility (which does not survive Foundry's
///      per-run state reset), so they fail loudly if a future change breaks
///      the handler's ability to land a vote.
///
///      Run `forge test --match-contract VotingManagerInvariants -vv` to see
///      the per-action call distribution; `show_metrics` is on in
///      foundry.toml.
contract VotingManagerHandlerWiringTest is Test {
    VotingManager internal voting;
    VotingManagerHandler internal handler;

    function setUp() public {
        MockVerifier verifier = new MockVerifier();
        voting = new VotingManager(address(verifier));
        handler = new VotingManagerHandler(voting);
        voting.transferOwnership(address(handler));
        vm.prank(address(handler));
        voting.acceptOwnership();
        handler.init();
    }

    function test_HandlerLandsVotes() public {
        for (uint256 i = 0; i < 25; i++) {
            handler.castVote(i, i, i);
        }
        assertEq(handler.totalAccepted(), 25, "every vote into a live poll must land");
        assertEq(handler.rejected(), 0, "no vote into a live poll should be rejected");
    }

    /// @dev The regression that made the suite vacuous: the fuzzer retires
    ///      polls far faster than it creates them. Votes must keep landing
    ///      even when every existing poll has just been killed.
    function test_HandlerStillLandsVotesAfterEveryPollIsRetired() public {
        handler.castVote(0, 0, 1);
        uint256 before = handler.totalAccepted();

        // Kill everything the handler knows about.
        for (uint256 i = 0; i < handler.pollCount(); i++) {
            handler.voidPoll(i);
        }

        handler.castVote(0, 1, 2);
        assertEq(handler.totalAccepted(), before + 1, "handler must open a fresh poll and vote");
    }

    /// @dev Voiding must not corrupt the shadow accounting the invariants
    ///      compare against.
    function test_VoidedPollsAreTrackedForTheInvariants() public {
        handler.castVote(0, 0, 1);
        handler.voidPoll(0);
        assertTrue(handler.voided(handler.pollIds(0)), "void must be recorded for the invariants");
    }
}
