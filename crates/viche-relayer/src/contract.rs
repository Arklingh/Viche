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
//! address + provider in [`crate::relay::submit_vote`].
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
///
/// Type mapping (alloy 0.8 sol-types):
///   * `uint256`       → `U256`
///   * `bytes calldata` → `Bytes`
///   * `bytes32`        → `FixedBytes<32>`  (= `B256`)
sol! {
    #[sol(rpc)]
    interface IVotingManager {
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
