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

#[cfg(test)]
mod tests {
    use super::*;

    // Function selectors, pinned as a regression guard: a signature change
    // (param order/types) would silently break on-chain calls without this.
    const CREATE_POLL_SELECTOR: [u8; 4] = [0x32, 0xee, 0x52, 0xc1];
    const OWNER_SELECTOR: [u8; 4] = [0x8d, 0xa5, 0xcb, 0x5b];

    #[test]
    fn encode_create_poll_selector_is_stable() {
        let root = FixedBytes::<32>::from([0x11u8; 32]);
        let data = encode_create_poll(root, 3, 1_893_456_000, "ipfs://demo");
        assert_eq!(&data[..4], &CREATE_POLL_SELECTOR);
    }

    #[test]
    fn encode_create_poll_round_trips_through_abi_decode() {
        let root = FixedBytes::<32>::from([0xabu8; 32]);
        let data = encode_create_poll(root, 5, 1_893_456_000, "ipfs://demo-poll");

        let decoded = createPollCall::abi_decode(&data, true).unwrap();
        assert_eq!(decoded.merkleRoot, root);
        assert_eq!(decoded.numOptions, U256::from(5u64));
        assert_eq!(decoded.deadline, U256::from(1_893_456_000u64));
        assert_eq!(decoded.metadataUri, "ipfs://demo-poll");
    }

    #[test]
    fn encode_create_poll_handles_empty_metadata_uri() {
        let root = FixedBytes::<32>::ZERO;
        let data = encode_create_poll(root, 2, 1, "");
        let decoded = createPollCall::abi_decode(&data, true).unwrap();
        assert_eq!(decoded.metadataUri, "");
    }

    #[test]
    fn encode_close_poll_round_trips_through_abi_decode() {
        let data = encode_close_poll(42);
        let decoded = closePollCall::abi_decode(&data, true).unwrap();
        assert_eq!(decoded.pollId, U256::from(42u64));
    }

    #[test]
    fn encode_owner_selector_is_stable_and_takes_no_args() {
        let data = encode_owner();
        assert_eq!(data, OWNER_SELECTOR);
    }

    #[test]
    fn decode_owner_extracts_low_20_bytes() {
        // 32-byte word: 12 zero bytes, then a 20-byte address.
        let addr_bytes = [0x11u8; 20];
        let mut resp = vec![0u8; 12];
        resp.extend_from_slice(&addr_bytes);
        let owner = decode_owner(&resp).unwrap();
        let expected = Address::from_slice(&addr_bytes).to_string();
        assert_eq!(owner, expected);
    }

    #[test]
    fn decode_owner_ignores_extra_trailing_bytes() {
        // eth_call responses are always exactly one 32-byte word for a
        // single `address` return, but decode_owner should not choke on more.
        let addr_bytes = [0x22u8; 20];
        let mut resp = vec![0u8; 12];
        resp.extend_from_slice(&addr_bytes);
        resp.extend_from_slice(&[0xffu8; 32]); // garbage second word
        let owner = decode_owner(&resp).unwrap();
        assert_eq!(owner, Address::from_slice(&addr_bytes).to_string());
    }

    #[test]
    fn decode_owner_rejects_short_response() {
        let resp = vec![0u8; 31];
        let err = decode_owner(&resp).unwrap_err();
        assert!(err.to_string().contains("short eth_call response"));
    }

    #[test]
    fn decode_owner_rejects_empty_response() {
        assert!(decode_owner(&[]).is_err());
    }

    #[test]
    fn parse_bytes32_accepts_0x_prefixed_hex() {
        let input = format!("0x{}", "ab".repeat(32));
        let parsed = parse_bytes32(&input).unwrap();
        assert_eq!(parsed, FixedBytes::<32>::from([0xabu8; 32]));
    }

    #[test]
    fn parse_bytes32_accepts_hex_without_prefix() {
        let input = "cd".repeat(32);
        let parsed = parse_bytes32(&input).unwrap();
        assert_eq!(parsed, FixedBytes::<32>::from([0xcdu8; 32]));
    }

    #[test]
    fn parse_bytes32_trims_whitespace() {
        let input = format!("  0x{}  ", "11".repeat(32));
        assert!(parse_bytes32(&input).is_ok());
    }

    #[test]
    fn parse_bytes32_rejects_wrong_length() {
        let short = format!("0x{}", "ab".repeat(10));
        let err = parse_bytes32(&short).unwrap_err();
        assert!(err.to_string().contains("expected 32 bytes"));

        let long = format!("0x{}", "ab".repeat(33));
        assert!(parse_bytes32(&long).is_err());
    }

    #[test]
    fn parse_bytes32_rejects_invalid_hex() {
        let input = format!("0x{}", "zz".repeat(32));
        assert!(parse_bytes32(&input).is_err());
    }

    #[test]
    fn parse_bytes32_rejects_empty_input() {
        assert!(parse_bytes32("").is_err());
        assert!(parse_bytes32("0x").is_err());
    }
}

#[cfg(test)]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn parse_datetime_local_unix_parses_a_valid_datetime() {
        // 2030-01-01T00:00 UTC == 1_893_456_000. `datetime-local` values are
        // interpreted in the local timezone, so just assert it's in the right
        // ballpark (within a day) rather than pinning an exact offset.
        let secs = parse_datetime_local_unix("2030-01-01T00:00").unwrap();
        let expected = 1_893_456_000u64;
        let diff = secs.abs_diff(expected);
        assert!(diff < 24 * 3600, "parsed timestamp {} too far from {}", secs, expected);
    }

    #[wasm_bindgen_test]
    fn parse_datetime_local_unix_rejects_empty_input() {
        assert_eq!(parse_datetime_local_unix(""), None);
        assert_eq!(parse_datetime_local_unix("   "), None);
    }

    #[wasm_bindgen_test]
    fn parse_datetime_local_unix_rejects_garbage_input() {
        assert_eq!(parse_datetime_local_unix("not-a-date"), None);
    }
}
