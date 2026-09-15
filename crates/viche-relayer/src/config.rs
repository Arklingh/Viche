//! Relayer configuration, loaded from environment variables.
//!
//! All sensitive values (private key, RPC URL) come from `.env` via
//! [`dotenvy`]. Non-secret defaults are hardcoded so a dev environment
//! (anvil on `:8545`) works with minimal setup.
//!
//! ## Defaults are the *secure* option, not the convenient one
//!
//! Every knob added for hardening (CORS, proxy trust, rate limits, body
//! caps, the registration eligibility gate) defaults to the restrictive
//! setting. A deployer must opt *out* explicitly. The one place this bites
//! is [`EligibilityPolicyKind`]: it defaults to `invite-code`, and boot fails
//! loudly if no invite codes were configured, rather than silently falling
//! back to an open (Sybil-farmable) endpoint. `.env.example` sets
//! `REGISTRATION_ELIGIBILITY=open` for the local dev loop and says so.

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, U256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// Startup configuration. Constructed from env vars at boot.
#[derive(Debug, Clone)]
pub struct Config {
    /// The relayer's funded EOA private key (hex, may or may not have 0x).
    /// Only ever used to relay `castVote` — it has no special on-chain
    /// privilege (`castVote` isn't access-controlled).
    pub relayer_private_key: PrivateKeySigner,
    /// The `VotingManager.owner` private key, used to sign `createPoll` /
    /// `closePoll`. Deliberately a *separate* key from
    /// [`Self::relayer_private_key`] so a compromised relayer gas wallet
    /// can't also administer polls.
    pub admin_private_key: PrivateKeySigner,
    /// Shared secret required (as `Authorization: Bearer <key>`) to call the
    /// `/api/admin/*` routes.
    pub admin_api_key: String,
    /// JSON-RPC endpoint URL.
    pub rpc_url: String,
    /// On-chain `VotingManager` address.
    pub voting_manager_address: Address,
    /// Listen address for the HTTP server.
    pub listen_addr: SocketAddr,
    /// Path to the voter-registration store's JSON file (see
    /// [`crate::registration`]). Created on first write if missing.
    pub registrations_file: PathBuf,
    /// HTTP middleware knobs — CORS, rate limits, body caps, timeouts.
    pub http: HttpConfig,
    /// Spend guards on the relayer's gas wallet.
    pub gas: GasConfig,
    /// Readiness-probe thresholds.
    pub health: HealthConfig,
    /// Sybil-resistance knobs for `POST /api/register`.
    pub registration: RegistrationConfig,
}

// =========================================================================
// HTTP middleware
// =========================================================================

/// One per-IP token-bucket rule: `burst` tokens, refilled at
/// `per_minute / 60` tokens per second.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitRule {
    /// Sustained rate, in requests per minute.
    pub per_minute: u32,
    /// Bucket capacity — how many requests may arrive back-to-back before
    /// the sustained rate starts to bite.
    pub burst: u32,
}

impl RateLimitRule {
    /// Tokens added per second of elapsed wall-clock time.
    pub fn refill_per_second(&self) -> f64 {
        f64::from(self.per_minute) / 60.0
    }
}

/// Everything the HTTP layer needs that isn't a route or a provider.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Exact origins allowed to make cross-origin requests. Empty means
    /// "no cross-origin access at all" — the production topology is a
    /// reverse proxy serving the SPA and `/api` from one origin, so nothing
    /// needs CORS. Never `*`: these endpoints spend the relayer's ETH.
    pub cors_allowed_origins: Vec<String>,
    /// Whether to believe `X-Forwarded-For` / `X-Real-IP` when deciding
    /// which IP a request came from. Defaults to `false`: with this off, an
    /// attacker cannot reset their own rate-limit bucket by inventing a
    /// header. Turn it on *only* when a proxy you control strips and
    /// rewrites those headers.
    pub trust_proxy_headers: bool,
    /// How many proxies sit between the client and this process. Used to
    /// index into the `X-Forwarded-For` chain from the right-hand (nearest)
    /// end, so only hops you actually control are skipped.
    pub trusted_proxy_hops: usize,
    /// Per-IP limit on `POST /api/vote` (spends relayer ETH).
    pub rate_limit_vote: RateLimitRule,
    /// Per-IP limit on `POST /api/register` (grows persistent state).
    pub rate_limit_register: RateLimitRule,
    /// Per-IP limit on the read-only poll/tally endpoints.
    pub rate_limit_read: RateLimitRule,
    /// Per-IP limit on `/api/admin/*` (also throttles API-key guessing).
    pub rate_limit_admin: RateLimitRule,
    /// Cap on distinct IPs tracked by each limiter, so a spoofed-header or
    /// IPv6-rotation flood can't grow the bucket map without bound.
    pub rate_limit_max_tracked_ips: usize,
    /// Body cap for `POST /api/vote`. A well-formed vote is a 256-byte proof
    /// plus three small scalars — under 800 bytes of JSON.
    pub max_vote_body_bytes: usize,
    /// Body cap for `POST /api/register` (one scalar).
    pub max_register_body_bytes: usize,
    /// Body cap for `/api/admin/*` (an approval list can be large).
    pub max_admin_body_bytes: usize,
    /// Body cap for every other route.
    pub max_body_bytes: usize,
    /// Whole-request deadline. A hung RPC backend turns into a 504 instead
    /// of an in-flight request that never completes.
    pub request_timeout: Duration,
    /// Maximum simultaneously in-flight requests. Over this, the relayer
    /// sheds load with 503 rather than queueing without bound.
    pub max_concurrent_requests: usize,
}

// =========================================================================
// Gas / health / registration
// =========================================================================

/// Spend guards on the relayer's gas wallet.
#[derive(Debug, Clone)]
pub struct GasConfig {
    /// Hard ceiling on `maxFeePerGas`, in wei. A transaction whose estimated
    /// fee exceeds this is rejected with a clear error instead of broadcast,
    /// so a gas spike can't drain the relayer wallet unattended.
    pub max_fee_per_gas_wei: u128,
}

/// Readiness thresholds for `GET /ready`.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Below this relayer-wallet balance (wei), readiness fails with 503 —
    /// the relayer can no longer reliably pay for votes.
    pub min_balance_wei: U256,
    /// Below this balance (wei) but at or above [`Self::min_balance_wei`],
    /// readiness reports `degraded` (still 200) so monitoring can page
    /// before the wallet actually runs dry.
    pub low_balance_wei: U256,
}

/// Which eligibility gate `POST /api/register` enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EligibilityPolicyKind {
    /// Anyone may register. Sybil-farmable by construction — only sensible
    /// for local development or a community that reviews every batch by
    /// hand before snapshotting.
    Open,
    /// The request must carry an `X-Invite-Code` header matching a
    /// configured code that still has uses left. The default.
    InviteCode,
    /// The submitted commitment must appear in a pre-shared allowlist file.
    Allowlist,
}

impl FromStr for EligibilityPolicyKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "open" => Ok(Self::Open),
            "invite-code" | "invite_code" | "invite" => Ok(Self::InviteCode),
            "allowlist" | "allow-list" => Ok(Self::Allowlist),
            _ => Err(()),
        }
    }
}

/// Sybil-resistance knobs for the public registration endpoint.
#[derive(Debug, Clone)]
pub struct RegistrationConfig {
    /// Which eligibility gate to install (see [`crate::eligibility`]).
    pub policy: EligibilityPolicyKind,
    /// Invite code -> optional maximum number of uses (`None` = unlimited).
    /// Only meaningful for [`EligibilityPolicyKind::InviteCode`].
    pub invite_codes: HashMap<String, Option<u32>>,
    /// Path to a newline-separated commitment allowlist. Only meaningful for
    /// [`EligibilityPolicyKind::Allowlist`].
    pub allowlist_file: Option<PathBuf>,
    /// When true (the default), a commitment must be explicitly approved by
    /// the admin before `snapshot` will include it in a batch.
    pub require_approval: bool,
    /// Maximum pending registrations attributable to one source (client IP,
    /// stored only as a salted hash — see [`crate::registration`]).
    pub max_per_source: usize,
    /// Maximum total pending registrations in a single batch.
    pub max_pending: usize,
}

// =========================================================================
// Loading
// =========================================================================

impl Config {
    /// Load configuration from environment variables (optionally `.env`).
    ///
    /// # Required env vars
    ///
    /// - `RELAYER_PRIVATE_KEY` — hex private key for the funded relayer EOA.
    /// - `ADMIN_PRIVATE_KEY`   — hex private key for the `VotingManager`
    ///   owner (signs `createPoll`/`closePoll`). Should be a different key
    ///   from `RELAYER_PRIVATE_KEY` in any real deployment.
    /// - `ADMIN_API_KEY`       — shared secret guarding `/api/admin/*`.
    /// - `RPC_URL`              — JSON-RPC endpoint (e.g. `http://127.0.0.1:8545`).
    /// - `VOTING_MANAGER_ADDRESS` — deployed `VotingManager` contract address.
    ///
    /// Every optional var, its default, and why the default is what it is,
    /// is documented in `.env.example`.
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load .env if present (no-op if the file doesn't exist).
        let _ = dotenvy::dotenv();

        let raw_key = std::env::var("RELAYER_PRIVATE_KEY")
            .map_err(|_| ConfigError::Missing("RELAYER_PRIVATE_KEY"))?;
        let relayer_private_key = parse_signer(&raw_key)?;

        let raw_admin_key = std::env::var("ADMIN_PRIVATE_KEY")
            .map_err(|_| ConfigError::Missing("ADMIN_PRIVATE_KEY"))?;
        let admin_private_key = parse_signer(&raw_admin_key)?;

        let admin_api_key =
            std::env::var("ADMIN_API_KEY").map_err(|_| ConfigError::Missing("ADMIN_API_KEY"))?;
        if admin_api_key.trim().is_empty() {
            return Err(ConfigError::EmptyAdminApiKey);
        }

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

        let registrations_file = std::env::var("REGISTRATIONS_FILE")
            .unwrap_or_else(|_| "registrations.json".into())
            .into();

        Ok(Self {
            relayer_private_key,
            admin_private_key,
            admin_api_key,
            rpc_url,
            voting_manager_address,
            listen_addr,
            registrations_file,
            http: HttpConfig::from_env()?,
            gas: GasConfig::from_env()?,
            health: HealthConfig::from_env()?,
            registration: RegistrationConfig::from_env()?,
        })
    }
}

impl HttpConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let cors_allowed_origins = parse_csv_list(
            &std::env::var("CORS_ALLOWED_ORIGINS").unwrap_or_default(),
        );
        for origin in &cors_allowed_origins {
            if origin == "*" {
                return Err(ConfigError::WildcardCors);
            }
            if !origin.starts_with("http://") && !origin.starts_with("https://") {
                return Err(ConfigError::InvalidOrigin(origin.clone()));
            }
        }

        let trust_proxy_headers = env_bool("TRUST_PROXY_HEADERS", false)?;
        let trusted_proxy_hops = env_usize("TRUSTED_PROXY_HOPS", 1)?;
        if trust_proxy_headers && trusted_proxy_hops == 0 {
            return Err(ConfigError::Invalid(
                "TRUSTED_PROXY_HOPS must be at least 1 when TRUST_PROXY_HEADERS=true",
            ));
        }

        Ok(Self {
            cors_allowed_origins,
            trust_proxy_headers,
            trusted_proxy_hops,
            rate_limit_vote: rate_rule("VOTE", 5, 5)?,
            rate_limit_register: rate_rule("REGISTER", 3, 3)?,
            rate_limit_read: rate_rule("READ", 120, 60)?,
            rate_limit_admin: rate_rule("ADMIN", 60, 30)?,
            rate_limit_max_tracked_ips: env_usize("RATE_LIMIT_MAX_TRACKED_IPS", 100_000)?,
            max_vote_body_bytes: env_usize("MAX_VOTE_BODY_BYTES", 4_096)?,
            max_register_body_bytes: env_usize("MAX_REGISTER_BODY_BYTES", 1_024)?,
            max_admin_body_bytes: env_usize("MAX_ADMIN_BODY_BYTES", 1_048_576)?,
            max_body_bytes: env_usize("MAX_BODY_BYTES", 16_384)?,
            request_timeout: Duration::from_secs(env_u64("REQUEST_TIMEOUT_SECS", 20)?),
            max_concurrent_requests: env_usize("MAX_CONCURRENT_REQUESTS", 64)?,
        })
    }
}

/// Read one `RATE_LIMIT_<NAME>_PER_MINUTE` / `..._BURST` pair.
fn rate_rule(name: &str, per_minute: u32, burst: u32) -> Result<RateLimitRule, ConfigError> {
    let rule = RateLimitRule {
        per_minute: env_u32(&format!("RATE_LIMIT_{name}_PER_MINUTE"), per_minute)?,
        burst: env_u32(&format!("RATE_LIMIT_{name}_BURST"), burst)?,
    };
    if rule.per_minute == 0 || rule.burst == 0 {
        return Err(ConfigError::Invalid(
            "rate-limit per-minute and burst must both be greater than zero",
        ));
    }
    Ok(rule)
}

impl GasConfig {
    fn from_env() -> Result<Self, ConfigError> {
        // Expressed in gwei because that is the unit people actually reason
        // about when they look at a gas tracker.
        let gwei = env_u64("MAX_FEE_PER_GAS_GWEI", 150)?;
        if gwei == 0 {
            return Err(ConfigError::Invalid(
                "MAX_FEE_PER_GAS_GWEI must be greater than zero",
            ));
        }
        Ok(Self {
            max_fee_per_gas_wei: u128::from(gwei) * 1_000_000_000u128,
        })
    }
}

impl HealthConfig {
    fn from_env() -> Result<Self, ConfigError> {
        // 0.01 ETH hard floor, 0.05 ETH warning floor. At a 150 gwei
        // ceiling and ~300k gas per vote, 0.01 ETH is roughly 200 votes.
        let min_balance_wei = env_u256("RELAYER_MIN_BALANCE_WEI", 10_000_000_000_000_000u128)?;
        let low_balance_wei = env_u256("RELAYER_LOW_BALANCE_WEI", 50_000_000_000_000_000u128)?;
        if low_balance_wei < min_balance_wei {
            return Err(ConfigError::Invalid(
                "RELAYER_LOW_BALANCE_WEI must be >= RELAYER_MIN_BALANCE_WEI",
            ));
        }
        Ok(Self {
            min_balance_wei,
            low_balance_wei,
        })
    }
}

impl RegistrationConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let raw_policy =
            std::env::var("REGISTRATION_ELIGIBILITY").unwrap_or_else(|_| "invite-code".into());
        let policy = EligibilityPolicyKind::from_str(&raw_policy)
            .map_err(|_| ConfigError::InvalidEligibilityPolicy(raw_policy))?;

        let invite_codes =
            parse_invite_codes(&std::env::var("REGISTRATION_INVITE_CODES").unwrap_or_default())?;
        let allowlist_file = std::env::var("REGISTRATION_ALLOWLIST_FILE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        // Refuse to boot in a configuration that *looks* gated but isn't.
        // Silently degrading to "everyone is eligible" is exactly the
        // failure mode this whole gate exists to prevent.
        match policy {
            EligibilityPolicyKind::InviteCode if invite_codes.is_empty() => {
                return Err(ConfigError::EligibilityNotConfigured(
                    "REGISTRATION_ELIGIBILITY=invite-code requires REGISTRATION_INVITE_CODES \
                     (set it, or set REGISTRATION_ELIGIBILITY=open to deliberately accept \
                     registrations from anyone)",
                ));
            }
            EligibilityPolicyKind::Allowlist if allowlist_file.is_none() => {
                return Err(ConfigError::EligibilityNotConfigured(
                    "REGISTRATION_ELIGIBILITY=allowlist requires REGISTRATION_ALLOWLIST_FILE",
                ));
            }
            _ => {}
        }

        let max_per_source = env_usize("REGISTRATION_MAX_PER_SOURCE", 5)?;
        let max_pending = env_usize("REGISTRATION_MAX_PENDING", 10_000)?;
        if max_per_source == 0 || max_pending == 0 {
            return Err(ConfigError::Invalid(
                "REGISTRATION_MAX_PER_SOURCE and REGISTRATION_MAX_PENDING must be > 0",
            ));
        }

        Ok(Self {
            policy,
            invite_codes,
            allowlist_file,
            require_approval: env_bool("REGISTRATION_REQUIRE_APPROVAL", true)?,
            max_per_source,
            max_pending,
        })
    }
}

// =========================================================================
// Parsing helpers
// =========================================================================

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

/// Split a comma-separated env value into trimmed, non-empty entries.
pub(crate) fn parse_csv_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse `REGISTRATION_INVITE_CODES`: `code`, or `code:max_uses`, repeated
/// and comma-separated. A bare code has unlimited uses; `code:0` is rejected
/// as almost certainly a mistake (a code nobody can use).
pub(crate) fn parse_invite_codes(raw: &str) -> Result<HashMap<String, Option<u32>>, ConfigError> {
    let mut out = HashMap::new();
    for entry in parse_csv_list(raw) {
        let (code, max_uses) = match entry.rsplit_once(':') {
            Some((code, uses)) => {
                let parsed: u32 = uses
                    .trim()
                    .parse()
                    .map_err(|_| ConfigError::InvalidInviteCode(entry.clone()))?;
                if parsed == 0 {
                    return Err(ConfigError::InvalidInviteCode(entry.clone()));
                }
                (code.trim().to_string(), Some(parsed))
            }
            None => (entry.clone(), None),
        };
        if code.is_empty() {
            return Err(ConfigError::InvalidInviteCode(entry));
        }
        out.insert(code, max_uses);
    }
    Ok(out)
}

fn env_bool(key: &str, default: bool) -> Result<bool, ConfigError> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "" => Ok(default),
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(ConfigError::InvalidValue(key.to_string())),
        },
    }
}

fn env_usize(key: &str, default: usize) -> Result<usize, ConfigError> {
    env_parsed(key, default)
}

fn env_u32(key: &str, default: u32) -> Result<u32, ConfigError> {
    env_parsed(key, default)
}

fn env_u64(key: &str, default: u64) -> Result<u64, ConfigError> {
    env_parsed(key, default)
}

fn env_u256(key: &str, default: u128) -> Result<U256, ConfigError> {
    match std::env::var(key) {
        Err(_) => Ok(U256::from(default)),
        Ok(raw) if raw.trim().is_empty() => Ok(U256::from(default)),
        Ok(raw) => U256::from_str_radix(raw.trim(), 10)
            .map_err(|_| ConfigError::InvalidValue(key.to_string())),
    }
}

fn env_parsed<T: FromStr>(key: &str, default: T) -> Result<T, ConfigError> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) if raw.trim().is_empty() => Ok(default),
        Ok(raw) => raw
            .trim()
            .parse()
            .map_err(|_| ConfigError::InvalidValue(key.to_string())),
    }
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
    /// `ADMIN_API_KEY` was set but blank.
    #[error("ADMIN_API_KEY must not be empty")]
    EmptyAdminApiKey,
    /// An optional env var was set to something unparseable.
    #[error("invalid value for env var: {0}")]
    InvalidValue(String),
    /// A combination of values that can't be honoured.
    #[error("{0}")]
    Invalid(&'static str),
    /// `CORS_ALLOWED_ORIGINS` contained `*`.
    #[error(
        "CORS_ALLOWED_ORIGINS must not contain '*': these endpoints spend the relayer's ETH, \
         so list exact origins (or leave it empty for same-origin-only)"
    )]
    WildcardCors,
    /// A CORS origin was not an absolute http(s) origin.
    #[error("invalid CORS origin '{0}' (expected e.g. https://vote.example.org)")]
    InvalidOrigin(String),
    /// `REGISTRATION_ELIGIBILITY` was not one of the known policies.
    #[error("invalid REGISTRATION_ELIGIBILITY '{0}' (expected open|invite-code|allowlist)")]
    InvalidEligibilityPolicy(String),
    /// The chosen eligibility policy has no data to work with.
    #[error("{0}")]
    EligibilityNotConfigured(&'static str),
    /// A `REGISTRATION_INVITE_CODES` entry was malformed.
    #[error("invalid invite code entry '{0}' (expected 'code' or 'code:max_uses')")]
    InvalidInviteCode(String),
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

    // ---- parse_csv_list --------------------------------------------------

    #[test]
    fn parse_csv_list_trims_and_drops_blanks() {
        assert_eq!(
            parse_csv_list(" https://a.example , ,https://b.example "),
            vec!["https://a.example", "https://b.example"]
        );
        assert!(parse_csv_list("").is_empty());
        assert!(parse_csv_list("  ,  ").is_empty());
    }

    // ---- parse_invite_codes ----------------------------------------------

    #[test]
    fn parse_invite_codes_accepts_bare_and_capped_entries() {
        let codes = parse_invite_codes("alpha,beta:3").unwrap();
        assert_eq!(codes.get("alpha"), Some(&None));
        assert_eq!(codes.get("beta"), Some(&Some(3)));
    }

    #[test]
    fn parse_invite_codes_rejects_zero_and_garbage_limits() {
        assert!(parse_invite_codes("alpha:0").is_err());
        assert!(parse_invite_codes("alpha:many").is_err());
        assert!(parse_invite_codes(":5").is_err());
    }

    #[test]
    fn parse_invite_codes_is_empty_for_blank_input() {
        assert!(parse_invite_codes("").unwrap().is_empty());
    }

    // ---- EligibilityPolicyKind -------------------------------------------

    #[test]
    fn eligibility_policy_parses_known_spellings() {
        assert_eq!(
            "open".parse::<EligibilityPolicyKind>().unwrap(),
            EligibilityPolicyKind::Open
        );
        assert_eq!(
            "Invite-Code".parse::<EligibilityPolicyKind>().unwrap(),
            EligibilityPolicyKind::InviteCode
        );
        assert_eq!(
            " allowlist ".parse::<EligibilityPolicyKind>().unwrap(),
            EligibilityPolicyKind::Allowlist
        );
        assert!("whatever".parse::<EligibilityPolicyKind>().is_err());
    }

    // ---- RateLimitRule ---------------------------------------------------

    #[test]
    fn rate_limit_rule_refills_at_per_minute_over_sixty() {
        let rule = RateLimitRule {
            per_minute: 60,
            burst: 10,
        };
        assert!((rule.refill_per_second() - 1.0).abs() < f64::EPSILON);
    }
}
