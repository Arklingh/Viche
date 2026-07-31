// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title IVotingManager
/// @notice Public ABI of `VotingManager`. The relayer (Rust/alloy) and the
///         Leptos frontend bind against THIS interface — it gives them a
///         stable, slim view of the contract independent of internal helpers
///         and storage layout.
interface IVotingManager {
    // -------------------------------------------------------------------------
    // Events
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

    // -------------------------------------------------------------------------
    // Admin
    // -------------------------------------------------------------------------
    function createPoll(
        bytes32 merkleRoot,
        uint256 numOptions,
        uint256 deadline,
        string calldata metadataUri
    ) external returns (uint256 pollId);

    function closePoll(uint256 pollId) external;

    function transferOwnership(address newOwner) external;

    // -------------------------------------------------------------------------
    // Voting
    // -------------------------------------------------------------------------

    /// @dev `proof` is `abi.encode(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)`.
    function castVote(
        uint256 pollId,
        bytes calldata proof,
        bytes32 nullifierHash,
        uint256 voteOption
    ) external;

    // -------------------------------------------------------------------------
    // Views
    // -------------------------------------------------------------------------
    function verifier() external view returns (address);
    function owner() external view returns (address);
    function nextPollId() external view returns (uint256);

    function getPoll(uint256 pollId)
        external
        view
        returns (
            bytes32 merkleRoot,
            uint256 deadline,
            uint256 numOptions,
            uint256 totalVotes,
            bool active
        );

    function getOptionTally(uint256 pollId, uint256 voteOption) external view returns (uint256);
    function hasVoted(uint256 pollId, bytes32 nullifierHash) external view returns (bool);
}
