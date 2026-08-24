//! Direct on-chain calls for poll administration.
//!
//! `createPoll`/`closePoll` are `onlyOwner`-gated in `VotingManager.sol`, so
//! rather than routing them through the relayer (which never holds a
//! privileged key — it only ever signs `castVote` on the voter's behalf, see
//! `viche-relayer::relay::submit_vote`), the admin wallet signs and
//! broadcasts these transactions directly via the injected EIP-1193
//! provider. The contract's `onlyOwner` modifier is the authorization
//! boundary; the frontend only mirrors it for UX (hiding the admin page from
//! non-owners) and re-checks nothing server-side.

use alloy_primitives::{Address, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};
use anyhow::{anyhow, Result};

sol! {
    interface IVotingManagerAdmin {
        function createPoll(
            bytes32 merkleRoot,
            uint256 numOptions,
            uint256 deadline,
            string metadataUri
        ) external returns (uint256 pollId);

        function closePoll(uint256 pollId) external;

        function owner() external view returns (address);
    }
}

use IVotingManagerAdmin::{closePollCall, createPollCall, ownerCall};

/// Build the calldata for `createPoll(bytes32,uint256,uint256,string)`.
pub fn encode_create_poll(
    merkle_root: FixedBytes<32>,
    num_options: u64,
    deadline: u64,
    metadata_uri: &str,
) -> Vec<u8> {
    createPollCall {
        merkleRoot: merkle_root,
        numOptions: U256::from(num_options),
        deadline: U256::from(deadline),
        metadataUri: metadata_uri.to_string(),
    }
    .abi_encode()
}

/// Build the calldata for `closePoll(uint256)`.
pub fn encode_close_poll(poll_id: u64) -> Vec<u8> {
    closePollCall {
        pollId: U256::from(poll_id),
    }
    .abi_encode()
}

/// Build the calldata for the `owner()` view call.
pub fn encode_owner() -> Vec<u8> {
    ownerCall {}.abi_encode()
}

/// Decode the raw `owner()` return value: a right-padded 32-byte word with
/// the address in its low 20 bytes (standard Solidity ABI encoding).
pub fn decode_owner(resp: &[u8]) -> Result<String> {
    if resp.len() < 32 {
        return Err(anyhow!(
            "short eth_call response ({} bytes, expected >= 32)",
            resp.len()
        ));
    }
    Ok(Address::from_slice(&resp[12..32]).to_string())
}

/// Parse a `0x`-prefixed 32-byte hex string into `bytes32`.
pub fn parse_bytes32(input: &str) -> Result<FixedBytes<32>> {
    let trimmed = input.trim().trim_start_matches("0x");
    let bytes =
        alloy_primitives::hex::decode(trimmed).map_err(|e| anyhow!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes, got {}", bytes.len()));
    }
    Ok(FixedBytes::from_slice(&bytes))
}

/// Parse an `<input type="datetime-local">` value into a Unix timestamp
/// (seconds). Interpreted in the browser's local timezone via JS `Date`,
/// since the frontend carries no timezone-aware date library.
pub fn parse_datetime_local_unix(input: &str) -> Option<u64> {
    if input.trim().is_empty() {
        return None;
    }
    let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_str(input));
    let millis = date.get_time();
    if millis.is_nan() || millis < 0.0 {
        return None;
    }
    Some((millis / 1000.0) as u64)
}
