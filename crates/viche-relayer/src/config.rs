//! Relayer configuration, loaded from environment variables.
//!
//! All sensitive values (private key, RPC URL) come from `.env` via
//! [`dotenvy`]. Non-secret defaults are hardcoded so a dev environment
//! (anvil on `:8545`) works with minimal setup.

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::Address;
use std::net::SocketAddr;
use std::str::FromStr;

/// Startup configuration. Constructed from env vars at boot.
#[derive(Debug, Clone)]
pub struct Config {
    /// The relayer's funded EOA private key (hex, may or may not have 0x).
    pub relayer_private_key: PrivateKeySigner,
    /// JSON-RPC endpoint URL.
    pub rpc_url: String,
    /// On-chain `VotingManager` address.
    pub voting_manager_address: Address,
    /// Listen address for the HTTP server.
    pub listen_addr: SocketAddr,
}

impl Config {
    /// Load configuration from environment variables (optionally `.env`).
    ///
    /// # Required env vars
    ///
    /// - `RELAYER_PRIVATE_KEY` — hex private key for the funded relayer EOA.
    /// - `RPC_URL`              — JSON-RPC endpoint (e.g. `http://127.0.0.1:8545`).
    /// - `VOTING_MANAGER_ADDRESS` — deployed `VotingManager` contract address.
    ///
    /// # Optional env vars (with defaults)
    ///
    /// - `RELAYER_LISTEN_ADDR` — default `0.0.0.0`
    /// - `RELAYER_LISTEN_PORT` — default `3000`
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load .env if present (no-op if the file doesn't exist).
        let _ = dotenvy::dotenv();

        let raw_key = std::env::var("RELAYER_PRIVATE_KEY")
            .map_err(|_| ConfigError::Missing("RELAYER_PRIVATE_KEY"))?;
        let relayer_private_key = parse_signer(&raw_key)?;

        let rpc_url = std::env::var("RPC_URL").map_err(|_| ConfigError::Missing("RPC_URL"))?;

        let raw_addr = std::env::var("VOTING_MANAGER_ADDRESS")
            .map_err(|_| ConfigError::Missing("VOTING_MANAGER_ADDRESS"))?;
        let voting_manager_address: Address = raw_addr
            .parse()
            .map_err(|_| ConfigError::InvalidAddress(raw_addr))?;

        let host = std::env::var("RELAYER_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0".into());
        let port: u16 = std::env::var("RELAYER_LISTEN_PORT")
            .unwrap_or_else(|_| "3000".into())
            .parse()
            .map_err(|_| ConfigError::InvalidPort)?;
        let listen_addr =
            SocketAddr::from_str(&format!("{}:{}", host, port)).expect("invalid socket addr");

        Ok(Self {
            relayer_private_key,
            rpc_url,
            voting_manager_address,
            listen_addr,
        })
    }
}

/// Parse a hex private key string into a [`PrivateKeySigner`].
///
/// Accepts both `0x`-prefixed and raw hex, and strips whitespace.
fn parse_signer(s: &str) -> Result<PrivateKeySigner, ConfigError> {
    let hex_str = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let bytes = hex::decode(hex_str).map_err(|_| ConfigError::InvalidPrivateKey)?;
    if bytes.len() != 32 {
        return Err(ConfigError::InvalidPrivateKey);
    }
    PrivateKeySigner::from_slice(&bytes).map_err(|_| ConfigError::InvalidPrivateKey)
}

/// Configuration loading errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required env var is missing.
    #[error("missing required env var: {0}")]
    Missing(&'static str),
    /// The private key is not a valid 32-byte hex scalar.
    #[error("invalid private key (must be 32 bytes hex)")]
    InvalidPrivateKey,
    /// The contract address is not a valid hex address.
    #[error("invalid contract address: {0}")]
    InvalidAddress(String),
    /// The listen port is not a valid u16.
    #[error("invalid listen port")]
    InvalidPort,
}

#[cfg(test)]
mod tests {
    use super::*;

    // anvil account #0 private key.
    const ANVIL_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn parse_anvil_key() {
        let signer = parse_signer(ANVIL_KEY).unwrap();
        // anvil account #0 address.
        assert_eq!(
            format!("{:?}", signer.address()),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn parse_key_without_0x_prefix() {
        let stripped = &ANVIL_KEY[2..]; // drop "0x"
        assert!(parse_signer(stripped).is_ok());
    }

    #[test]
    fn reject_short_key() {
        assert!(parse_signer("0xdeadbeef").is_err());
    }

    #[test]
    fn reject_empty_key() {
        assert!(parse_signer("").is_err());
    }
}
