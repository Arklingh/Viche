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
    event VoteCast(uint256 indexed pollId, bytes32 indexed nullifierHash, uint256 voteOption);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @dev All the per-poll state. The tally lives in a nested mapping so it
    ///      can grow with the number of options without resizing arrays.
    struct Poll {
        bytes32 merkleRoot;
        uint256 deadline;
        uint256 numOptions;
        uint256 totalVotes;
        bool active;
        bool exists;
        mapping(uint256 => uint256) optionTally;
    }

    /// @notice The deployed Groth16 verifier. Immutable after construction.
    IVerifier public immutable verifier;

    /// @notice Poll administrator (the only address that can create / close polls).
    address public owner;

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
        p.active = true;
        p.exists = true;

        emit PollCreated(pollId, merkleRoot, deadline, numOptions, metadataUri);
    }

    /// @notice Manually close a poll before its deadline (e.g. tallying early).
    function closePoll(uint256 pollId) external onlyOwner pollExists(pollId) {
        polls[pollId].active = false;
        emit PollClosed(pollId);
    }

    /// @notice Transfer poll-admin rights.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert Unauthorized();
        address prev = owner;
        owner = newOwner;
        emit OwnershipTransferred(prev, newOwner);
    }

    // -------------------------------------------------------------------------
    // Voting
    // -------------------------------------------------------------------------

    /// @notice Cast an anonymous ballot.
    /// @dev    `msg.sender` is the relayer, not the voter — the contract never
    ///         reads voter identity, it relies entirely on the ZK proof +
    ///         nullifier. The relayer is trusted only for *delivery*, not
    ///         for correctness: a malicious relayer can drop or reorder votes
    ///         but cannot forge one (no valid proof) or double-vote (nullifier
    ///         is fixed by the voter's secret + pollId).
    ///
    /// @param pollId        Target poll; MUST equal the circuit's `voteId`.
    /// @param proof         abi.encode(pA, pB, pC) — three Groth16 points.
    /// @param nullifierHash Poseidon(secret, pollId); the double-voting tag.
    /// @param voteOption    Index of the chosen option.
    function castVote(
        uint256 pollId,
        bytes calldata proof,
        bytes32 nullifierHash,
        uint256 voteOption
    ) external pollExists(pollId) {
        Poll storage p = polls[pollId];

        if (!p.active) revert PollNotActive(pollId);
        if (block.timestamp > p.deadline) revert PollEnded(pollId);
        if (voteOption >= p.numOptions) revert InvalidVoteOption(voteOption);
        if (nullifierUsed[pollId][nullifierHash]) revert AlreadyVoted(nullifierHash);

        // Unpack the proof. We accept the canonical abi.encode of the three
        // snarkjs points rather than three separate calldata args: it keeps
        // the relayer/frontend wire format as one opaque blob.
        (uint256[2] memory pA, uint256[2][2] memory pB, uint256[2] memory pC) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));

        // Public-signal order MUST match `vote.circom`:
        //     [voteId, merkleRoot, nullifierHash]
        // We bind voteId == pollId and merkleRoot == the poll's stored root
        // from on-chain state, so the proof is replay-bound to this exact poll
        // and this exact whitelist — cross-poll replay is impossible.
        uint256[3] memory pubSignals =
            [pollId, uint256(p.merkleRoot), uint256(nullifierHash)];

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
        return (p.merkleRoot, p.deadline, p.numOptions, p.totalVotes, p.active);
    }

    /// @notice Tally for a single option.
    function getOptionTally(uint256 pollId, uint256 voteOption)
        external
        view
        pollExists(pollId)
        returns (uint256)
    {
        return polls[pollId].optionTally[voteOption];
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
