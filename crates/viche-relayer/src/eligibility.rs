//! Pluggable eligibility gate for `POST /api/register`.
//!
//! ## Why this is a trait and not a policy
//!
//! Who is allowed to join a community's electorate is a *community*
//! question — a token balance, a mailing-list membership, a government ID, a
//! conference badge. The relayer cannot answer it, and any answer baked into
//! this crate would be wrong for most deployers. So this module ships the
//! **mechanism**: a trait, a registration pipeline that calls it before
//! anything is persisted, and three implementations covering the cases that
//! need no external service.
//!
//! A deployer with a real eligibility source implements
//! [`EligibilityPolicy`] against it and swaps it in at construction, without
//! forking the crate:
//!
//! ```ignore
//! struct TokenHolderPolicy { dao: MyDao }
//!
//! impl EligibilityPolicy for TokenHolderPolicy {
//!     fn name(&self) -> &'static str { "token-holder" }
//!     fn check(&self, req: &EligibilityRequest<'_>) -> Result<EligibilityGrant, EligibilityDenied> {
//!         // ... consult your own source of truth ...
//!         Ok(EligibilityGrant::new("token-holder"))
//!     }
//! }
//!
//! // in main.rs, in place of `build_policy(&cfg.registration)?`:
//! let policy: Arc<dyn EligibilityPolicy> = Arc::new(TokenHolderPolicy { dao });
//! ```
//!
//! ## Shipped implementations
//!
//! | `REGISTRATION_ELIGIBILITY` | gate | configured by |
//! |---|---|---|
//! | `invite-code` *(default)* | request must carry `X-Invite-Code` matching a code with uses left | `REGISTRATION_INVITE_CODES=code[:max_uses],…` |
//! | `allowlist` | the submitted commitment must appear in a pre-shared file | `REGISTRATION_ALLOWLIST_FILE=/path/to/list` |
//! | `open` | none — anyone may register | — |
//!
//! `invite-code` is the default *because* it is non-trivial: it is the
//! weakest gate that still forces an attacker to obtain something out of
//! band per registration, and it needs no infrastructure beyond an env var.
//! Per-code use caps make an invite a spendable budget, so a leaked code
//! costs at most its cap rather than the whole electorate.
//!
//! `open` exists because local development needs it, and because a community
//! that reviews every batch by hand before snapshotting (see
//! `REGISTRATION_REQUIRE_APPROVAL` in [`crate::registration`]) has moved the
//! gate to the approval step instead. It must be selected explicitly —
//! [`crate::config`] refuses to boot into `open` by omission.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

use alloy_primitives::U256;

use crate::config::{EligibilityPolicyKind, RegistrationConfig};

/// Everything a policy may inspect about a registration attempt.
///
/// Deliberately small and borrow-only: a policy sees the commitment, the
/// invite code if one was presented, and an opaque, salted source id (never
/// a raw IP — see [`crate::registration`] on why the store refuses to hold
/// one).
#[derive(Debug, Clone, Copy)]
pub struct EligibilityRequest<'a> {
    /// The identity commitment being registered.
    pub commitment: &'a U256,
    /// Value of the `X-Invite-Code` header, if present.
    pub invite_code: Option<&'a str>,
    /// Opaque, stable, salted identifier for the submitting network source.
    pub source_id: &'a str,
}

/// A granted registration, carrying the provenance the admin later reviews.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibilityGrant {
    /// Short machine-readable note recorded against the registration, e.g.
    /// `invite-code:spring-2026` or `open`. Surfaced verbatim in the admin
    /// review endpoint.
    pub note: String,
}

impl EligibilityGrant {
    /// Build a grant with the given provenance note.
    pub fn new(note: impl Into<String>) -> Self {
        Self { note: note.into() }
    }
}

/// A refused registration. The message is returned to the client verbatim,
/// so it must not leak which codes exist or how many uses remain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct EligibilityDenied(pub String);

impl EligibilityDenied {
    /// Build a denial with the given client-visible reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// The eligibility gate `POST /api/register` consults before persisting
/// anything.
///
/// Implementations must be cheap and non-blocking — this runs inline on the
/// request path, behind the endpoint's rate limiter but ahead of any disk
/// write. A policy that needs to talk to a network service should cache
/// aggressively or move the lookup to the approval step instead.
pub trait EligibilityPolicy: Send + Sync + 'static {
    /// Stable identifier for logs and the readiness payload.
    fn name(&self) -> &'static str;

    /// Decide whether this registration may proceed.
    fn check(&self, req: &EligibilityRequest<'_>) -> Result<EligibilityGrant, EligibilityDenied>;
}

// =========================================================================
// Open
// =========================================================================

/// Accepts every registration. Sybil-farmable by construction.
#[derive(Debug, Default)]
pub struct OpenPolicy;

impl EligibilityPolicy for OpenPolicy {
    fn name(&self) -> &'static str {
        "open"
    }

    fn check(&self, _req: &EligibilityRequest<'_>) -> Result<EligibilityGrant, EligibilityDenied> {
        Ok(EligibilityGrant::new("open"))
    }
}

// =========================================================================
// Invite code
// =========================================================================

/// Requires a valid, unexhausted invite code in the `X-Invite-Code` header.
///
/// Use counting is in-memory: a restart resets every counter. That is a
/// deliberate simplification — the counter is a blast-radius limiter on a
/// leaked code, not an accounting ledger, and the admin approval step in
/// [`crate::registration`] is the authoritative control. A deployer who
/// needs durable counts should implement [`EligibilityPolicy`] against their
/// own store.
#[derive(Debug)]
pub struct InviteCodePolicy {
    /// code -> optional maximum uses.
    codes: HashMap<String, Option<u32>>,
    /// code -> uses so far this process lifetime.
    used: Mutex<HashMap<String, u32>>,
}

impl InviteCodePolicy {
    /// Build a policy over the configured codes.
    pub fn new(codes: HashMap<String, Option<u32>>) -> Self {
        Self {
            codes,
            used: Mutex::new(HashMap::new()),
        }
    }

    /// Uses recorded against `code` so far. Test/metrics helper.
    pub fn uses(&self, code: &str) -> u32 {
        self.lock().get(code).copied().unwrap_or(0)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, u32>> {
        match self.used.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// One message for "no code", "wrong code" and "exhausted code" alike, so
/// the endpoint can't be used to enumerate which codes exist or how much
/// budget a known code has left.
const INVITE_DENIED: &str =
    "a valid invite code is required to register (send it as the X-Invite-Code header)";

impl EligibilityPolicy for InviteCodePolicy {
    fn name(&self) -> &'static str {
        "invite-code"
    }

    fn check(&self, req: &EligibilityRequest<'_>) -> Result<EligibilityGrant, EligibilityDenied> {
        let Some(code) = req.invite_code else {
            return Err(EligibilityDenied::new(INVITE_DENIED));
        };
        let Some(max_uses) = self.codes.get(code) else {
            return Err(EligibilityDenied::new(INVITE_DENIED));
        };

        let mut used = self.lock();
        let counter = used.entry(code.to_string()).or_insert(0);
        if let Some(max) = max_uses {
            if *counter >= *max {
                return Err(EligibilityDenied::new(INVITE_DENIED));
            }
        }
        *counter += 1;

        Ok(EligibilityGrant::new(format!("invite-code:{code}")))
    }
}

// =========================================================================
// Allowlist
// =========================================================================

/// Requires the submitted commitment to appear in a pre-shared list.
///
/// The natural fit when the community can compute each member's commitment
/// out of band (e.g. a registration desk that runs `Poseidon(secret)` for
/// each attendee) — the gate then needs no per-request secret at all.
#[derive(Debug)]
pub struct AllowlistPolicy {
    allowed: HashSet<U256>,
}

impl AllowlistPolicy {
    /// Build a policy over an explicit commitment set.
    pub fn new(allowed: HashSet<U256>) -> Self {
        Self { allowed }
    }

    /// Load from a newline-separated file of commitments (decimal, or
    /// `0x`-prefixed hex). Blank lines and `#` comments are ignored.
    pub fn from_file(path: &Path) -> Result<Self, AllowlistError> {
        let text = std::fs::read_to_string(path).map_err(|e| AllowlistError::Read {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(Self::new(parse_allowlist(&text)?))
    }

    /// Number of allowed commitments. Test/metrics helper.
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Whether the allowlist is empty.
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

impl EligibilityPolicy for AllowlistPolicy {
    fn name(&self) -> &'static str {
        "allowlist"
    }

    fn check(&self, req: &EligibilityRequest<'_>) -> Result<EligibilityGrant, EligibilityDenied> {
        if self.allowed.contains(req.commitment) {
            Ok(EligibilityGrant::new("allowlist"))
        } else {
            Err(EligibilityDenied::new(
                "this identity commitment is not on the eligibility allowlist",
            ))
        }
    }
}

/// Parse an allowlist file body into a commitment set.
pub fn parse_allowlist(text: &str) -> Result<HashSet<U256>, AllowlistError> {
    let mut out = HashSet::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let parsed = match line.strip_prefix("0x").or_else(|| line.strip_prefix("0X")) {
            Some(hex) => U256::from_str_radix(hex, 16),
            None => U256::from_str_radix(line, 10),
        };
        let value = parsed.map_err(|_| AllowlistError::Parse {
            line: lineno + 1,
            value: line.to_string(),
        })?;
        out.insert(value);
    }
    Ok(out)
}

/// Failures loading an allowlist file.
#[derive(Debug, thiserror::Error)]
pub enum AllowlistError {
    /// The file could not be read.
    #[error("failed to read allowlist file {path}: {source}")]
    Read {
        /// The path that could not be read.
        path: String,
        /// The underlying IO error.
        source: std::io::Error,
    },
    /// A line was not a valid commitment.
    #[error("invalid commitment on allowlist line {line}: '{value}'")]
    Parse {
        /// 1-based line number.
        line: usize,
        /// The offending text.
        value: String,
    },
}

/// Build the configured policy.
///
/// Called once at boot. [`crate::config::RegistrationConfig::from_env`] has
/// already refused any configuration whose policy has nothing to enforce, so
/// the only failure left here is an unreadable or malformed allowlist file.
pub fn build_policy(
    cfg: &RegistrationConfig,
) -> Result<std::sync::Arc<dyn EligibilityPolicy>, AllowlistError> {
    Ok(match cfg.policy {
        EligibilityPolicyKind::Open => {
            tracing::warn!(
                "registration eligibility is OPEN: anyone may submit identity commitments. \
                 Sybil resistance rests entirely on the per-source cap and the admin \
                 approval step. Set REGISTRATION_ELIGIBILITY=invite-code or =allowlist \
                 for anything public."
            );
            std::sync::Arc::new(OpenPolicy)
        }
        EligibilityPolicyKind::InviteCode => {
            tracing::info!(
                codes = cfg.invite_codes.len(),
                "registration eligibility: invite-code"
            );
            std::sync::Arc::new(InviteCodePolicy::new(cfg.invite_codes.clone()))
        }
        EligibilityPolicyKind::Allowlist => {
            let path = cfg
                .allowlist_file
                .as_ref()
                .expect("config guarantees an allowlist path for the allowlist policy");
            let policy = AllowlistPolicy::from_file(path)?;
            tracing::info!(
                entries = policy.len(),
                path = %path.display(),
                "registration eligibility: allowlist"
            );
            std::sync::Arc::new(policy)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(commitment: &'a U256, invite_code: Option<&'a str>) -> EligibilityRequest<'a> {
        EligibilityRequest {
            commitment,
            invite_code,
            source_id: "src-abc",
        }
    }

    // ---- OpenPolicy ------------------------------------------------------

    #[test]
    fn open_policy_admits_everything() {
        let c = U256::from(1u64);
        let grant = OpenPolicy.check(&req(&c, None)).unwrap();
        assert_eq!(grant.note, "open");
        assert_eq!(OpenPolicy.name(), "open");
    }

    // ---- InviteCodePolicy ------------------------------------------------

    fn invite_policy() -> InviteCodePolicy {
        let mut codes = HashMap::new();
        codes.insert("unlimited".to_string(), None);
        codes.insert("capped".to_string(), Some(2));
        InviteCodePolicy::new(codes)
    }

    #[test]
    fn invite_policy_admits_a_known_code_and_records_provenance() {
        let c = U256::from(1u64);
        let grant = invite_policy().check(&req(&c, Some("unlimited"))).unwrap();
        assert_eq!(grant.note, "invite-code:unlimited");
    }

    #[test]
    fn invite_policy_rejects_a_missing_code() {
        let c = U256::from(1u64);
        assert!(invite_policy().check(&req(&c, None)).is_err());
    }

    #[test]
    fn invite_policy_rejects_an_unknown_code() {
        let c = U256::from(1u64);
        assert!(invite_policy().check(&req(&c, Some("nope"))).is_err());
    }

    #[test]
    fn invite_policy_enforces_the_per_code_use_cap() {
        let policy = invite_policy();
        let c = U256::from(1u64);
        assert!(policy.check(&req(&c, Some("capped"))).is_ok());
        assert!(policy.check(&req(&c, Some("capped"))).is_ok());
        assert!(policy.check(&req(&c, Some("capped"))).is_err());
        assert_eq!(policy.uses("capped"), 2);
    }

    #[test]
    fn invite_policy_does_not_consume_a_use_on_rejection() {
        let policy = invite_policy();
        let c = U256::from(1u64);
        assert!(policy.check(&req(&c, Some("nope"))).is_err());
        assert_eq!(policy.uses("nope"), 0);
        assert_eq!(policy.uses("capped"), 0);
    }

    #[test]
    fn an_unlimited_code_never_exhausts() {
        let policy = invite_policy();
        let c = U256::from(1u64);
        for _ in 0..100 {
            assert!(policy.check(&req(&c, Some("unlimited"))).is_ok());
        }
    }

    #[test]
    fn invite_denials_are_indistinguishable_from_one_another() {
        // Absent / unknown / exhausted must not be tellable apart, or the
        // endpoint becomes a code oracle.
        let policy = invite_policy();
        let c = U256::from(1u64);
        let absent = policy.check(&req(&c, None)).unwrap_err();
        let unknown = policy.check(&req(&c, Some("nope"))).unwrap_err();
        policy.check(&req(&c, Some("capped"))).unwrap();
        policy.check(&req(&c, Some("capped"))).unwrap();
        let exhausted = policy.check(&req(&c, Some("capped"))).unwrap_err();
        assert_eq!(absent, unknown);
        assert_eq!(unknown, exhausted);
    }

    // ---- AllowlistPolicy -------------------------------------------------

    #[test]
    fn allowlist_policy_admits_only_listed_commitments() {
        let policy = AllowlistPolicy::new(HashSet::from([U256::from(7u64)]));
        assert!(policy.check(&req(&U256::from(7u64), None)).is_ok());
        assert!(policy.check(&req(&U256::from(8u64), None)).is_err());
        assert_eq!(policy.len(), 1);
        assert!(!policy.is_empty());
    }

    #[test]
    fn parse_allowlist_handles_decimal_hex_comments_and_blanks() {
        let text = "\
# eligible voters
42

0x2a   # same value, hex
  1234
";
        let set = parse_allowlist(text).unwrap();
        assert!(set.contains(&U256::from(42u64)));
        assert!(set.contains(&U256::from(1234u64)));
        // 42 and 0x2a dedupe to one entry.
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn parse_allowlist_rejects_a_bad_line_with_its_number() {
        let err = parse_allowlist("1\nnot-a-number\n").unwrap_err();
        match err {
            AllowlistError::Parse { line, ref value } => {
                assert_eq!(line, 2);
                assert_eq!(value, "not-a-number");
            }
            other => panic!("expected a parse error, got {other:?}"),
        }
    }

    #[test]
    fn parse_allowlist_of_only_comments_is_empty_not_an_error() {
        assert!(parse_allowlist("# nothing here\n\n").unwrap().is_empty());
    }

    #[test]
    fn allowlist_from_a_missing_file_is_an_error_not_an_empty_list() {
        // Silently admitting nobody would look like a working gate; silently
        // admitting everybody would be a disaster. Fail instead.
        let path = std::env::temp_dir().join("viche-no-such-allowlist-file.txt");
        assert!(AllowlistPolicy::from_file(&path).is_err());
    }
}
