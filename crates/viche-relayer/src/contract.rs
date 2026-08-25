//! On-chain contract binding for `IVotingManager`.
//!
//! We use the [`alloy_sol_types::sol!`] macro to generate a Rust-native ABI
//! binding from the Solidity function signatures. This gives us:
//!
//!   * Type-safe argument lists (no dynamic `DynSolValue` arrays).
//!   * Compile-time selector verification (a typo in the function name or a
//!     type mismatch fails at build, not at runtime).
//!
//! The generated `IVotingManager` struct is instantiated at the deployed
//! address + provider in [`crate::relay::submit_vote`] (relayer key) and
//! [`crate::relay::submit_create_poll`] / [`crate::relay::submit_close_poll`]
//! (admin key).
//!
//! NOTE: we bind to `IVotingManager` (the external interface), not
//! `VotingManager` (which has internal storage structs `sol!` cannot parse).
//! The `castVote` function is identical in both — only the ABI matters.

use alloy::sol;

/// Solidity interface for `VotingManager` — the subset the relayer calls.
///
/// `sol!` parses this at compile time and generates:
///   * `castVoteCall` — the call struct returned by `.castVote(...)`.
///   * `castVoteCall::send(&self)` — broadcast the transaction.
///   * `IVotingManager`   — the contract wrapper struct.
///   * `IVotingManager::castVote(...)` — method on the contract instance.
///   * `IVotingManager::IVotingManagerErrors` — an aggregate enum over every
///     `error` declared below (one variant per error), implementing
///     `SolInterface` so a revert's raw data can be decoded back into a
///     specific typed error — see [`crate::relay::submit_vote`]'s
///     pre-simulation step, which decodes against this instead of hand-typed
///     4-byte selectors (error-prone; a typo fails silently at runtime, not
///     at compile time like everything else in this file).
///
/// Type mapping (alloy 0.8 sol-types):
///   * `uint256`       → `U256`
///   * `bytes calldata` → `Bytes`
///   * `bytes32`        → `FixedBytes<32>`  (= `B256`)
sol! {
    #[sol(rpc)]
    interface IVotingManager {
        // ---- errors (VotingManager.sol's custom errors, verbatim) --------
        // Declared here (not just in the .sol source) purely so `sol!`
        // generates `IVotingManagerErrors` for decoding revert data — see
        // the module doc comment above.
        error Unauthorized();
        error PollDoesNotExist(uint256 pollId);
        error PollNotActive(uint256 pollId);
        error PollEnded(uint256 pollId);
        error InvalidVoteOption(uint256 voteOption);
        error AlreadyVoted(bytes32 nullifierHash);
        error InvalidProof();
        error InvalidDeadline();
        error InvalidNumOptions();

        /// @notice Create a new poll. Reverts (`Unauthorized`) if the caller
        ///         isn't `VotingManager.owner` — see [`crate::relay::submit_create_poll`].
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
            string metadataUri
        ) external returns (uint256 pollId);

        /// @notice Manually close a poll before its deadline. Reverts
        ///         (`Unauthorized`) if the caller isn't `VotingManager.owner`.
        function closePoll(uint256 pollId) external;

        /// @notice Cast an anonymous ballot.
        /// @param pollId        Target poll.
        /// @param proof         abi.encode(pA, pB, pC).
        /// @param nullifierHash Poseidon(secret, pollId).
        /// @param voteOption    Chosen option index.
        function castVote(
            uint256 pollId,
            bytes proof,
            bytes32 nullifierHash,
            uint256 voteOption
        ) external;

        /// @notice Core poll metadata (view).
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

        /// @notice Tally for a single option.
        function getOptionTally(uint256 pollId, uint256 voteOption)
            external
            view
            returns (uint256);

        /// @notice True if a ballot with this nullifier has already landed.
        function hasVoted(uint256 pollId, bytes32 nullifierHash)
            external
            view
            returns (bool);

        /// @notice Counter for the next poll id (starts at 1).
        function nextPollId() external view returns (uint256);
    }
}
