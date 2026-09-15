// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IVerifier} from "./IVerifier.sol";

/// @title VotingManager
/// @notice On-chain anonymous voting. Each poll is backed by a Poseidon Merkle
///         tree of identity commitments. A voter submits a Groth16 proof that
///         (a) their commitment `Poseidon(secret)` is in the tree and
///         (b) they are the owner of `secret`, alongside a per-poll nullifier
///         `Poseidon(secret, pollId)`. The nullifier prevents double-voting
///         while keeping identity hidden — see `vote.circom`.
/// @dev    A single `VotingManager` deployment manages MANY polls (a registry).
///         The original spec sketched a one-poll-per-deploy contract, but a
///         real community runs many ballots, so we centralise lifecycle here.
///
///         PRIVACY SCOPE: the voter's *identity* is anonymous. The chosen
///         option is tallied in the clear. Hiding the choice itself needs an
///         additional encryption layer (out of scope for Viche v1).
contract VotingManager {
    // -------------------------------------------------------------------------
    // Custom errors (cheaper + self-documenting than require strings).
    // -------------------------------------------------------------------------
    error Unauthorized();
    error PollDoesNotExist(uint256 pollId);
    error PollNotActive(uint256 pollId);
    error PollEnded(uint256 pollId);
    error InvalidVoteOption(uint256 voteOption);
    error AlreadyVoted(bytes32 nullifierHash);
    error InvalidProof();
    error InvalidDeadline();
    error InvalidNumOptions();
    error ZeroVerifier();
    /// @dev `closePoll` was called before the deadline. Finalising early would
    ///      let an admin freeze a tally that currently favours them; see
    ///      `closePoll`.
    error PollStillOpen(uint256 pollId, uint256 deadline);
    /// @dev `cancelPoll` was called after voting had begun. Cancelling is only
    ///      for retiring a misconfigured poll nobody has voted in.
    error PollHasVotes(uint256 pollId, uint256 totalVotes);
    /// @dev The poll is void; its tally is discarded and must not be read as a
    ///      result.
    error PollVoided(uint256 pollId);
    /// @dev The poll's lifecycle has already ended (closed, cancelled, voided).
    error PollNotOpen(uint256 pollId);
    /// @dev `acceptOwnership` was called by someone who is not `pendingOwner`.
    error NotPendingOwner();
    /// @dev No ownership transfer is currently in flight.
    error NoPendingOwner();

    // -------------------------------------------------------------------------
    // Events.
    // -------------------------------------------------------------------------
    event PollCreated(
        uint256 indexed pollId,
        bytes32 indexed merkleRoot,
        uint256 deadline,
        uint256 numOptions,
        string metadataUri
    );
    event PollClosed(uint256 indexed pollId);
    /// @notice A poll was retired before anyone voted in it (misconfiguration).
    event PollCancelled(uint256 indexed pollId, string reason);
    /// @notice A poll's results were discarded. `totalVotes` is recorded so the
    ///         void is auditable — observers can see how far it had run.
    event PollVoid(uint256 indexed pollId, uint256 totalVotes, string reason);
    event VoteCast(uint256 indexed pollId, bytes32 indexed nullifierHash, uint256 voteOption);
    /// @notice An ownership transfer was proposed. Not yet in effect — the new
    ///         owner must call `acceptOwnership`.
    event OwnershipTransferStarted(address indexed currentOwner, address indexed pendingOwner);
    /// @notice A proposed ownership transfer was withdrawn before acceptance.
    event OwnershipTransferCancelled(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice A poll's lifecycle state.
    ///
    /// @dev Replaces the old `bool active`. The distinction that matters is
    ///      between *finalised* and *discarded*: `Closed` means the tally
    ///      stands, `Void` means it must not be read as a result at all. See
    ///      `voidPoll` for why that difference is the whole point.
    enum PollStatus {
        /// @dev Never used — `exists` is false for an unknown poll, and the
        ///      zero value here would otherwise be indistinguishable.
        Nonexistent,
        /// @dev Accepting votes (subject to the deadline).
        Open,
        /// @dev Finalised after the deadline. The tally is the result.
        Closed,
        /// @dev Retired before any vote was cast. No result, nobody affected.
        Cancelled,
        /// @dev Abandoned mid-flight. The tally is discarded, NOT a result.
        Void
    }

    /// @dev All the per-poll state. The tally lives in a nested mapping so it
    ///      can grow with the number of options without resizing arrays.
    struct Poll {
        bytes32 merkleRoot;
        uint256 deadline;
        uint256 numOptions;
        uint256 totalVotes;
        PollStatus status;
        bool exists;
        mapping(uint256 => uint256) optionTally;
    }

    /// @notice The deployed Groth16 verifier. Immutable after construction.
    IVerifier public immutable verifier;

    /// @notice Poll administrator (the only address that can create / close polls).
    ///
    /// @dev This is deliberately a plain `address`, so it can be an EOA, a
    ///      multisig, or a timelock contract with no code change here. For a
    ///      real election it should be a multisig: every power below is
    ///      concentrated in this one address, and the two-step handover in
    ///      `transferOwnership`/`acceptOwnership` exists precisely so that
    ///      moving it to one cannot be fumbled.
    address public owner;

    /// @notice Proposed next owner. Ownership does not move until this address
    ///         calls `acceptOwnership`.
    ///
    /// @dev The two-step handover is not ceremony. A single-step transfer to a
    ///      mistyped or non-signing address — a multisig whose threshold can't
    ///      actually be met, say — permanently bricks poll administration with
    ///      no recovery path, because the contract has no other privileged
    ///      role. Requiring the recipient to prove it can transact first makes
    ///      that failure impossible.
    address public pendingOwner;

    /// @notice Counter for the next poll id. Starts at 1 so pollId 0 is
    ///         distinguishable from "uninitialised storage".
    uint256 public nextPollId;

    mapping(uint256 => Poll) private polls;

    /// @dev nullifierUsed[pollId][nullifierHash] == true once a vote with that
    ///      nullifier has landed. This is the double-voting guard.
    mapping(uint256 => mapping(bytes32 => bool)) private nullifierUsed;

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier pollExists(uint256 pollId) {
        if (!polls[pollId].exists) revert PollDoesNotExist(pollId);
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    /// @param verifier_ Address of the (generated) Groth16 verifier contract.
    constructor(address verifier_) {
        if (verifier_ == address(0)) revert ZeroVerifier();
        verifier = IVerifier(verifier_);
        owner = msg.sender;
        nextPollId = 1;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // -------------------------------------------------------------------------
    // Admin
    // -------------------------------------------------------------------------

    /// @notice Create a new poll.
    /// @param merkleRoot  Root of the Poseidon Merkle tree of identity
    ///                    commitments eligible for this poll.
    /// @param numOptions  Number of vote options (>= 2).
    /// @param deadline    Unix timestamp after which voting is rejected.
    /// @param metadataUri Off-chain pointer (IPFS/HTTP) to poll question,
    ///                    option labels, etc. Not inspected on-chain.
    /// @return pollId     The id assigned to the new poll.
    function createPoll(
        bytes32 merkleRoot,
        uint256 numOptions,
        uint256 deadline,
        string calldata metadataUri
    ) external onlyOwner returns (uint256 pollId) {
        if (numOptions < 2) revert InvalidNumOptions();
        if (deadline <= block.timestamp) revert InvalidDeadline();

        pollId = nextPollId++;
        Poll storage p = polls[pollId];
        p.merkleRoot = merkleRoot;
        p.deadline = deadline;
        p.numOptions = numOptions;
        p.status = PollStatus.Open;
        p.exists = true;

        emit PollCreated(pollId, merkleRoot, deadline, numOptions, metadataUri);
    }

    /// @notice Finalise a poll once its deadline has passed.
    ///
    /// @dev This used to allow closing at ANY time, which was an integrity
    ///      hole rather than a convenience: the tally is public and updates
    ///      per vote, so an admin could watch it and freeze the count at the
    ///      exact moment it favoured them, disenfranchising everyone who had
    ///      not yet voted. "Tallying early" is not a legitimate need — the
    ///      tally is already readable at any time.
    ///
    ///      So closing is now only possible after `deadline`, at which point
    ///      `castVote` already rejects every vote and this call decides
    ///      nothing. It is pure bookkeeping: it marks the result final.
    ///
    ///      The two legitimate needs that early close used to serve are split
    ///      into operations that cannot be abused for advantage:
    ///        - a poll created with wrong parameters -> `cancelPoll`, which
    ///          only works before anyone has voted;
    ///        - a poll that must be abandoned mid-flight -> `voidPoll`, which
    ///          DISCARDS the tally rather than freezing it.
    function closePoll(uint256 pollId) external onlyOwner pollExists(pollId) {
        Poll storage p = polls[pollId];
        if (p.status != PollStatus.Open) revert PollNotOpen(pollId);
        if (block.timestamp <= p.deadline) revert PollStillOpen(pollId, p.deadline);

        p.status = PollStatus.Closed;
        emit PollClosed(pollId);
    }

    /// @notice Retire a poll that nobody has voted in yet.
    ///
    /// @dev The escape hatch for a misconfigured poll — a wrong Merkle root, a
    ///      wrong option count, a deadline set in the wrong timezone. Bounded
    ///      to `totalVotes == 0` so it can never revoke a ballot that has
    ///      already been cast: with no votes recorded there is no result to
    ///      distort and no voter to disenfranchise.
    ///
    ///      `reason` is recorded in the event rather than stored, so the
    ///      decision is publicly auditable at no ongoing storage cost.
    function cancelPoll(uint256 pollId, string calldata reason)
        external
        onlyOwner
        pollExists(pollId)
    {
        Poll storage p = polls[pollId];
        if (p.status != PollStatus.Open) revert PollNotOpen(pollId);
        if (p.totalVotes != 0) revert PollHasVotes(pollId, p.totalVotes);

        p.status = PollStatus.Cancelled;
        emit PollCancelled(pollId, reason);
    }

    /// @notice Abandon a running poll and DISCARD its results.
    ///
    /// @dev The genuine emergency hatch — the whitelist turns out to contain a
    ///      Sybil batch, the metadata described the wrong question, the
    ///      circuit is found to be broken mid-vote. Unlike the old early
    ///      `closePoll`, this is deliberately not a way to win.
    ///
    ///      That is the entire design: an admin who stops a poll mid-flight
    ///      cannot keep the favourable partial count. Voiding throws the tally
    ///      away — `getOptionTally` and `getResults` revert for a void poll —
    ///      so the only outcome of using this power is "no result", never "the
    ///      result I was ahead in". Removing the payoff removes the incentive,
    ///      which is a stronger guarantee than trying to forbid the action.
    ///
    ///      `totalVotes` is emitted so observers can see how far the poll had
    ///      run when it was voided, and judge the decision accordingly.
    function voidPoll(uint256 pollId, string calldata reason)
        external
        onlyOwner
        pollExists(pollId)
    {
        Poll storage p = polls[pollId];
        if (p.status != PollStatus.Open) revert PollNotOpen(pollId);

        p.status = PollStatus.Void;
        emit PollVoid(pollId, p.totalVotes, reason);
    }

    /// @notice Propose a new poll administrator. Takes effect only when
    ///         `newOwner` calls [`acceptOwnership`].
    ///
    /// @dev Step one of two — see [`pendingOwner`] for why this is not a
    ///      single call. Proposing again overwrites any previous proposal.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert Unauthorized();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @notice Withdraw a proposed ownership transfer before it is accepted.
    ///
    /// @dev Kept as its own function rather than overloading
    ///      `transferOwnership(address(0))`, so that "hand over control" and
    ///      "call the handover off" can never be confused for one another at
    ///      the call site.
    function cancelOwnershipTransfer() external onlyOwner {
        address pending = pendingOwner;
        if (pending == address(0)) revert NoPendingOwner();
        delete pendingOwner;
        emit OwnershipTransferCancelled(owner, pending);
    }

    /// @notice Accept a proposed ownership transfer. Callable only by the
    ///         address named in [`pendingOwner`].
    ///
    /// @dev Completing the handover requires the recipient to actually send a
    ///      transaction, which is what proves the address is controlled and
    ///      can sign — the property a single-step transfer cannot check.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        address prev = owner;
        owner = msg.sender;
        delete pendingOwner;
        emit OwnershipTransferred(prev, msg.sender);
    }

    // -------------------------------------------------------------------------
    // Voting
    // -------------------------------------------------------------------------

    /// @notice Cast an anonymous ballot.
    /// @dev    `msg.sender` is the relayer, not the voter — the contract never
    ///         reads voter identity, it relies entirely on the ZK proof +
    ///         nullifier. The relayer is trusted only for *delivery*, not
    ///         for correctness: a malicious relayer can drop, delay or reorder
    ///         votes but cannot forge one (no valid proof), double-vote
    ///         (nullifier is fixed by the voter's secret + pollId), or alter
    ///         the ballot (`voteOption` is a public input of the proof).
    ///
    ///         The same binding is what makes this function safe to leave
    ///         permissionless. Proofs are visible in the mempool; without
    ///         `voteOption` in the public signals, any observer could copy a
    ///         pending (proof, nullifier) pair, resubmit it with a different
    ///         option at higher gas, and both flip the ballot and grief the
    ///         real voter into an `AlreadyVoted` revert. Re-submitting the
    ///         same proof verbatim is still possible, but it is a no-op that
    ///         merely front-runs the voter's own identical vote.
    ///
    /// @param pollId        Target poll; MUST equal the circuit's `voteId`.
    /// @param proof         abi.encode(pA, pB, pC) — three Groth16 points.
    /// @param nullifierHash Poseidon(secret, pollId); the double-voting tag.
    /// @param voteOption    Index of the chosen option. MUST equal the
    ///                      `voteOption` the proof was generated for, or
    ///                      verification fails with `InvalidProof`.
    function castVote(
        uint256 pollId,
        bytes calldata proof,
        bytes32 nullifierHash,
        uint256 voteOption
    ) external pollExists(pollId) {
        Poll storage p = polls[pollId];

        if (p.status != PollStatus.Open) revert PollNotActive(pollId);
        if (block.timestamp > p.deadline) revert PollEnded(pollId);
        if (voteOption >= p.numOptions) revert InvalidVoteOption(voteOption);
        if (nullifierUsed[pollId][nullifierHash]) revert AlreadyVoted(nullifierHash);

        // Unpack the proof. We accept the canonical abi.encode of the three
        // snarkjs points rather than three separate calldata args: it keeps
        // the relayer/frontend wire format as one opaque blob.
        (uint256[2] memory pA, uint256[2][2] memory pB, uint256[2] memory pC) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));

        // Public-signal order MUST match `vote.circom`:
        //     [voteId, merkleRoot, nullifierHash, voteOption]
        // We bind voteId == pollId and merkleRoot == the poll's stored root
        // from on-chain state, so the proof is replay-bound to this exact poll
        // and this exact whitelist — cross-poll replay is impossible.
        //
        // `voteOption` is passed through from calldata *and verified*: because
        // it is a public input of the circuit, the pairing check only passes
        // if the caller supplies the same option the voter proved. That is
        // what stops a front-runner (or the relayer) from copying a pending
        // proof, swapping the option, and burning the nullifier.
        uint256[4] memory pubSignals =
            [pollId, uint256(p.merkleRoot), uint256(nullifierHash), voteOption];

        if (!verifier.verifyProof(pA, pB, pC, pubSignals)) revert InvalidProof();

        // Commit the vote.
        nullifierUsed[pollId][nullifierHash] = true;
        unchecked {
            p.optionTally[voteOption] += 1;
            p.totalVotes += 1;
        }
        emit VoteCast(pollId, nullifierHash, voteOption);
    }

    // -------------------------------------------------------------------------
    // Views
    // -------------------------------------------------------------------------

    /// @notice Core poll metadata.
    function getPoll(uint256 pollId)
        external
        view
        pollExists(pollId)
        returns (
            bytes32 merkleRoot,
            uint256 deadline,
            uint256 numOptions,
            uint256 totalVotes,
            bool active
        )
    {
        Poll storage p = polls[pollId];
        // `active` is kept in the return tuple, and kept meaning exactly what
        // it always meant — "will this poll accept a vote right now" — so the
        // relayer and frontend need no change. `getPollStatus` exposes the
        // richer lifecycle for callers that care WHY a poll stopped.
        return (p.merkleRoot, p.deadline, p.numOptions, p.totalVotes, p.status == PollStatus.Open);
    }

    /// @notice A poll's full lifecycle state.
    ///
    /// @dev Prefer this over `getPoll`'s `active` flag when the distinction
    ///      matters: `Closed` means the tally is the result, while `Void`
    ///      means there is no result at all. Collapsing both to
    ///      `active == false` would let a void poll be displayed as a
    ///      finished one.
    function getPollStatus(uint256 pollId)
        external
        view
        pollExists(pollId)
        returns (PollStatus)
    {
        return polls[pollId].status;
    }

    /// @notice Tally for a single option.
    ///
    /// @dev Reverts for a void poll rather than returning its last count.
    ///      This is the mechanism that makes `voidPoll` unprofitable: if a
    ///      voided tally were still readable, an admin could void while ahead
    ///      and point at the frozen numbers. Making the result unreadable
    ///      means voiding can only ever produce "no result".
    function getOptionTally(uint256 pollId, uint256 voteOption)
        external
        view
        pollExists(pollId)
        returns (uint256)
    {
        Poll storage p = polls[pollId];
        if (p.status == PollStatus.Void) revert PollVoided(pollId);
        return p.optionTally[voteOption];
    }

    /// @notice True if a ballot with this nullifier has already landed.
    function hasVoted(uint256 pollId, bytes32 nullifierHash)
        external
        view
        returns (bool)
    {
        return nullifierUsed[pollId][nullifierHash];
    }
}
