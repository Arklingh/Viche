//! The voter's secret: where it comes from, where it's cached, how to back it
//! up.
//!
//! # The problem this module exists to solve
//!
//! The secret is the *entire* identity. `commitment = Poseidon(secret)` is
//! what the admin locks into a poll's Merkle root, and `nullifier =
//! Poseidon(secret, pollId)` is what stops a double vote. Lose the secret and
//! you cannot prove membership: your commitment sits in the tree forever as
//! dead weight and your ballot is simply gone. There is no reset, no support
//! desk, no on-chain recovery — the contract only ever sees hashes.
//!
//! The original implementation generated 32 random bytes, wrote them to
//! `localStorage` with `let _ = ...`, and called it a day. That has two
//! independent failure modes, both silent:
//!
//! 1. The write fails (private window, quota, blocked site data) and the
//!    voter registers a commitment whose pre-image evaporates on reload.
//! 2. The write succeeds and the voter clears their browser data, switches
//!    laptops, or opens the app in a different browser. Same outcome.
//!
//! # The fix: derive, don't generate
//!
//! The secret is now derived from an EIP-191 `personal_sign` signature over
//! [`DERIVATION_MESSAGE_V1`] — a fixed, domain-separated, **poll-independent**
//! constant:
//!
//! ```text
//! secret = reduce( keccak256( personal_sign(DERIVATION_MESSAGE_V1)[0..64] ) )
//! ```
//!
//! secp256k1 signing as every mainstream wallet implements it is
//! deterministic (RFC 6979), so the same wallet over the same message always
//! yields the same bytes, on any device, in any browser, forever.
//! `localStorage` is demoted from *source of truth* to *cache*: losing it
//! costs one extra signature prompt, not a ballot.
//!
//! Only the first 64 bytes (`r || s`) feed the hash. The trailing recovery id
//! `v` is deliberately excluded because wallets disagree about how to encode
//! it (`0x00`/`0x01` vs `0x1b`/`0x1c`), and a voter who switched wallet
//! software would otherwise derive a different — and therefore useless —
//! secret from the same key.
//!
//! ## The honest tradeoff
//!
//! This binds the voting identity to the wallet key. Concretely:
//!
//! * **A wallet compromise is a vote compromise.** Anyone who can sign with
//!   that key can re-derive the secret, and can therefore vote as that voter
//!   in any poll the commitment is registered in. Previously an attacker
//!   needed both the key (to be recognised as the account) *and* the browser
//!   profile holding the random secret. That second factor is gone.
//! * **A wallet key rotation is an identity loss.** Moving to a new key means
//!   a new secret and a new commitment, so the voter must register again
//!   before the next poll. The [export](backup_blob)/[import](parse_backup)
//!   panel is the escape hatch: export before rotating, import afterwards.
//! * **A malicious dApp on the same wallet can phish the identity.** The
//!   signed message is a public constant, so any site that can get the user
//!   to sign it learns their Viche secret. The message text says so in as many
//!   words; a CSP and a warning are the only real mitigations, and the message
//!   itself is version-tagged so it can be rotated if it is ever abused.
//!
//! We take that trade because the failure it removes (silent, permanent,
//! unrecoverable disenfranchisement) is strictly worse than the one it adds
//! (a compromise that already implies the attacker controls the voter's
//! account).
//!
//! # Migration
//!
//! Anyone who used the app before this change has a *random* secret under
//! `viche:secret:{address}`. Re-deriving would silently change their
//! commitment and invalidate a registration that may already be inside a live
//! poll's Merkle root — they would keep voting and keep being rejected, with
//! no explanation. So: **a stored secret always wins**, it is tagged
//! [`SecretOrigin::LegacyRandom`], and the switch to a derived secret happens
//! only when the voter asks for it via [`migrate_to_wallet_derived`], which
//! tells them in advance that they must register again.

use alloy_primitives::{keccak256, U256};

use crate::storage::{self, StorageError, WebStorage};

/// The exact message signed to derive a voter's secret.
///
/// Three properties matter and all three are load-bearing:
///
/// * **Fixed** — byte-for-byte stable across builds, or every deploy would
///   hand returning voters a different identity. ASCII-only, `\n` newlines:
///   no em dashes, no smart quotes, nothing that a re-encoding could mangle
///   into a different hash.
/// * **Domain-separated** — it names Viche, so a signature harvested by some
///   other dApp's prompt is not a Viche secret.
/// * **Poll-independent** — one identity spans every poll, which is what lets
///   a voter register once and vote in the polls built afterwards.
///
/// Bump the version line (and the constant name) if it ever has to change;
/// never edit it in place.
pub const DERIVATION_MESSAGE_V1: &str = "\
Viche anonymous voting - voter identity derivation

Sign this message to unlock your Viche voting identity.

This signature costs no gas, sends no transaction, and never leaves your
browser. Signing the same message with the same wallet always produces the
same voting secret, which is how you restore your identity on another device.

Anyone who can make you sign this exact message learns your Viche voting
secret. Only sign it on the Viche app you trust.

Domain: viche.vote
Version: 1
";

/// `localStorage` key prefix for the cached secret value.
///
/// Unchanged from the pre-derivation build on purpose: the migration path in
/// [`resolve`] depends on finding existing secrets exactly where they were
/// left.
const SECRET_KEY_PREFIX: &str = "viche:secret:";

/// `localStorage` key prefix for the secret's provenance tag.
const ORIGIN_KEY_PREFIX: &str = "viche:secret-origin:";

/// Where a secret came from. Stored alongside it so the UI can tell a voter
/// whether their identity is reproducible from the wallet or exists only in
/// this browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretOrigin {
    /// Derived from an EIP-191 signature over [`DERIVATION_MESSAGE_V1`].
    /// Reproducible on any device from the wallet alone.
    WalletDerivedV1,
    /// Randomly generated by an older build and stored only in this browser.
    /// **Not** reproducible; if this browser's data is cleared it is gone.
    LegacyRandom,
    /// Restored by the voter from a backup blob. Reproducibility depends on
    /// where it originally came from, so treat it like `LegacyRandom`: tell
    /// the voter to keep the backup.
    Imported,
}

impl SecretOrigin {
    /// The tag written to `localStorage`. Stable on-disk strings — changing
    /// one would make an existing tag unreadable and silently downgrade the
    /// secret to `LegacyRandom`.
    pub fn tag(self) -> &'static str {
        match self {
            SecretOrigin::WalletDerivedV1 => "wallet-derived-v1",
            SecretOrigin::LegacyRandom => "legacy-random",
            SecretOrigin::Imported => "imported",
        }
    }

    /// Parse a tag written by [`Self::tag`].
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag.trim() {
            "wallet-derived-v1" => Some(SecretOrigin::WalletDerivedV1),
            "legacy-random" => Some(SecretOrigin::LegacyRandom),
            "imported" => Some(SecretOrigin::Imported),
            _ => None,
        }
    }

    /// Whether this secret can be re-derived from the wallet after the
    /// browser's data is cleared.
    pub fn is_recoverable_from_wallet(self) -> bool {
        matches!(self, SecretOrigin::WalletDerivedV1)
    }

    /// One-line explanation for the backup panel.
    pub fn description(self) -> &'static str {
        match self {
            SecretOrigin::WalletDerivedV1 => {
                "Derived from your wallet signature. It can be restored on any device by \
                 connecting this wallet and signing again."
            }
            SecretOrigin::LegacyRandom => {
                "Randomly generated by an older version of Viche and stored only in this \
                 browser. Clearing site data or switching devices loses it permanently \
                 unless you export it below."
            }
            SecretOrigin::Imported => {
                "Restored from a backup you pasted in. Keep that backup: Viche cannot \
                 reproduce this value on its own."
            }
        }
    }
}

/// A resolved voter secret plus everything the UI needs to explain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterSecret {
    /// The field element itself.
    pub value: U256,
    /// Where it came from.
    pub origin: SecretOrigin,
    /// A non-fatal storage problem hit while caching it. The secret in
    /// `value` is usable *right now*; this says it may not survive a reload.
    /// Never `Some` without the UI showing it — that is the whole point.
    pub storage_warning: Option<StorageError>,
}

/// Why resolving, importing, or migrating a secret failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    /// No injected EIP-1193 provider.
    NoWallet,
    /// The user dismissed the signature prompt, or the provider refused.
    SigningFailed(String),
    /// Storage refused a write we cannot proceed without.
    Storage(StorageError),
    /// A pasted backup could not be parsed.
    BadBackup(String),
    /// A pasted value is not a BN254 scalar field element.
    OutOfField,
    /// A pasted value is zero, which would make the commitment a known
    /// constant that anyone could forge a membership proof against.
    Zero,
}

impl SecretError {
    /// The message shown to the voter.
    pub fn user_message(&self) -> String {
        match self {
            SecretError::NoWallet => "No EIP-1193 wallet found. Install MetaMask or similar, \
                 then reconnect: your voting identity is derived from your wallet."
                .to_string(),
            SecretError::SigningFailed(detail) => format!(
                "Could not derive your voting identity because the signature request was not \
                 completed ({detail}). Approve the \"Viche anonymous voting\" signature in \
                 your wallet - it costs no gas and authorises no transaction."
            ),
            SecretError::Storage(e) => e.user_message(),
            SecretError::BadBackup(detail) => {
                format!("That does not look like a Viche secret backup ({detail}).")
            }
            SecretError::OutOfField => "That value is too large to be a Viche voting secret \
                 (it must be below the BN254 field modulus). Paste the backup exactly as it \
                 was exported."
                .to_string(),
            SecretError::Zero => "A voting secret of zero is not usable - its commitment is a \
                 publicly known constant anyone could impersonate."
                .to_string(),
        }
    }
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.user_message())
    }
}

impl std::error::Error for SecretError {}

impl From<StorageError> for SecretError {
    fn from(e: StorageError) -> Self {
        SecretError::Storage(e)
    }
}

// ---- keys ----------------------------------------------------------------

/// `localStorage` key holding the secret for `address`.
///
/// The address is used exactly as the provider reported it (EIP-55
/// checksummed, in practice) rather than normalised, because normalising now
/// would move every existing user's key and strand their stored secret. With
/// derivation in place a case mismatch is merely one extra signature prompt,
/// not a lost identity, so the compatibility win is worth more than the
/// tidiness.
pub fn secret_storage_key(address: &str) -> String {
    format!("{SECRET_KEY_PREFIX}{address}")
}

/// `localStorage` key holding the provenance tag for `address`.
pub fn origin_storage_key(address: &str) -> String {
    format!("{ORIGIN_KEY_PREFIX}{address}")
}

// ---- derivation ----------------------------------------------------------

/// Hash a `personal_sign` signature into a BN254 scalar.
///
/// Pure and synchronous so the derivation itself is testable without a
/// wallet. See the module docs for why `v` is dropped.
pub fn derive_from_signature(signature: &[u8]) -> Result<U256, SecretError> {
    if signature.len() < 64 {
        return Err(SecretError::SigningFailed(format!(
            "wallet returned a {}-byte signature; expected at least 64",
            signature.len()
        )));
    }
    let digest = keccak256(&signature[..64]);
    let raw = U256::from_be_bytes::<32>(digest.0);
    // `reduce` maps the 256-bit digest into the field. The resulting bias is
    // ~2^-126 away from uniform, which is nowhere near exploitable.
    let secret = viche_core::field::reduce(&raw);
    if secret == U256::ZERO {
        // Cryptographically unreachable, but a zero secret is a total break
        // of the commitment, so refuse rather than "handle" it.
        return Err(SecretError::Zero);
    }
    Ok(secret)
}

/// Prompt the wallet and derive the secret for `address`.
async fn derive_with_wallet(address: &str) -> Result<U256, SecretError> {
    let wallet = crate::wallet::detect().ok_or(SecretError::NoWallet)?;
    let signature = wallet
        .personal_sign(address, DERIVATION_MESSAGE_V1)
        .await
        .map_err(|e| SecretError::SigningFailed(e.to_string()))?;
    derive_from_signature(&signature)
}

// ---- cache ---------------------------------------------------------------

/// Parse a stored secret value, rejecting anything not in the field.
fn parse_stored_value(raw: &str) -> Option<U256> {
    let v = U256::from_str_radix(raw.trim(), 10).ok()?;
    (viche_core::field::is_in_field(&v) && v != U256::ZERO).then_some(v)
}

/// Read the cached secret for `address`, if there is a usable one.
///
/// A value that fails to parse is reported as absent (the caller re-derives
/// and overwrites it) rather than as an error, mirroring the behaviour the
/// old `load_or_create_secret` had for corrupt storage.
pub fn cached(address: &str) -> Result<Option<VoterSecret>, StorageError> {
    let Some(raw) = storage::get(WebStorage::Local, &secret_storage_key(address))? else {
        return Ok(None);
    };
    let Some(value) = parse_stored_value(&raw) else {
        return Ok(None);
    };

    // A secret with no provenance tag predates this module, so it is a
    // *random* one. Assuming "derived" here would be the dangerous default:
    // it would tell the voter their identity is recoverable when it is not.
    let tag = storage::get(WebStorage::Local, &origin_storage_key(address))?;
    let origin = tag
        .as_deref()
        .and_then(SecretOrigin::from_tag)
        .unwrap_or(SecretOrigin::LegacyRandom);

    // Backfill the tag so the provenance is explicit from here on. Failing to
    // write a *label* must never block a vote, so this one is best-effort by
    // design — the secret it describes is already safely stored.
    if tag.is_none() {
        let _ = storage::set(
            WebStorage::Local,
            &origin_storage_key(address),
            origin.tag(),
        );
    }

    Ok(Some(VoterSecret {
        value,
        origin,
        storage_warning: None,
    }))
}

/// Write `value` and its provenance tag, surfacing any failure.
fn store(address: &str, value: U256, origin: SecretOrigin) -> Result<(), StorageError> {
    storage::set(
        WebStorage::Local,
        &secret_storage_key(address),
        &value.to_string(),
    )?;
    storage::set(
        WebStorage::Local,
        &origin_storage_key(address),
        origin.tag(),
    )
}

// ---- the public entry point ---------------------------------------------

/// Resolve the voter's secret for `address`: cache first, wallet derivation
/// second.
///
/// Never generates randomness. Never overwrites an existing secret. The
/// returned [`VoterSecret::storage_warning`] is `Some` when the derived value
/// could not be cached — the caller **must** show it, but need not abort,
/// because a derived secret is reproducible by definition.
pub async fn resolve(address: &str) -> Result<VoterSecret, SecretError> {
    // A failed *read* is not fatal: we can always ask the wallet again. It
    // does predict that the subsequent write will fail too, so remember it.
    let read_error = match cached(address) {
        Ok(Some(found)) => return Ok(found),
        Ok(None) => None,
        Err(e) => Some(e),
    };

    let value = derive_with_wallet(address).await?;
    let storage_warning = store(address, value, SecretOrigin::WalletDerivedV1)
        .err()
        .or(read_error);

    Ok(VoterSecret {
        value,
        origin: SecretOrigin::WalletDerivedV1,
        storage_warning,
    })
}

/// Replace a legacy random (or imported) secret with the wallet-derived one.
///
/// Explicit and voter-initiated, because it changes `Poseidon(secret)` — the
/// commitment already sitting in any poll whose whitelist was built from the
/// old value stops matching, and the voter has to register again before the
/// next poll. The UI must say that *before* calling this.
///
/// Unlike [`resolve`], a storage failure here is fatal: half-applying the
/// migration would leave the old secret in the cache and the next call would
/// silently hand back the pre-migration identity.
pub async fn migrate_to_wallet_derived(address: &str) -> Result<VoterSecret, SecretError> {
    let value = derive_with_wallet(address).await?;
    store(address, value, SecretOrigin::WalletDerivedV1)?;
    Ok(VoterSecret {
        value,
        origin: SecretOrigin::WalletDerivedV1,
        storage_warning: None,
    })
}

/// Store a secret the voter restored from a backup.
///
/// Fatal on a storage failure for the same reason as the migration: an
/// imported secret that does not persist will be re-derived on the next
/// reload, quietly reverting the restore the voter believes succeeded.
pub fn import(address: &str, value: U256) -> Result<VoterSecret, SecretError> {
    if value == U256::ZERO {
        return Err(SecretError::Zero);
    }
    if !viche_core::field::is_in_field(&value) {
        return Err(SecretError::OutOfField);
    }
    store(address, value, SecretOrigin::Imported)?;
    Ok(VoterSecret {
        value,
        origin: SecretOrigin::Imported,
        storage_warning: None,
    })
}

/// Forget the cached secret for `address`.
///
/// Safe for a wallet-derived secret (it comes back with one signature) and
/// **destructive** for a legacy or imported one — the UI warns accordingly.
pub fn forget(address: &str) -> Result<(), SecretError> {
    storage::remove(WebStorage::Local, &secret_storage_key(address))?;
    storage::remove(WebStorage::Local, &origin_storage_key(address))?;
    Ok(())
}

// ---- backup blob ---------------------------------------------------------

/// Version stamped into [`backup_blob`] output.
const BACKUP_VERSION: u64 = 1;

/// Serialise a secret into the blob the export panel shows.
///
/// Deliberately plain JSON with the value in decimal, matching how the secret
/// is stored and how the circuit consumes it: a voter must be able to eyeball
/// a backup and a `localStorage` entry and see that they agree.
pub fn backup_blob(address: &str, secret: &VoterSecret) -> String {
    let value = serde_json::json!({
        "viche_backup": BACKUP_VERSION,
        "address": address,
        "origin": secret.origin.tag(),
        "secret": secret.value.to_string(),
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| secret.value.to_string())
}

/// A parsed backup, before it is committed to storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedBackup {
    /// The secret itself.
    pub secret: U256,
    /// The address the backup was taken from, when the blob records one.
    /// Compared against the connected account so the UI can warn about
    /// importing someone else's (or another account's) identity.
    pub address: Option<String>,
    /// The origin recorded at export time, when present.
    pub origin: Option<SecretOrigin>,
}

/// Parse pasted text into a secret.
///
/// Accepts the full JSON blob from [`backup_blob`] *and* a bare value in
/// decimal or `0x` hex, because voters copy things out of `localStorage`
/// inspectors and half-select JSON all the time. Out-of-field values are
/// rejected rather than reduced: reducing would hand back a *different*
/// secret than the one backed up, and the mismatch would only surface later
/// as an unexplained "your commitment is not in this poll's whitelist".
pub fn parse_backup(input: &str) -> Result<ParsedBackup, SecretError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SecretError::BadBackup("nothing pasted".into()));
    }

    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let raw = map
            .get("secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SecretError::BadBackup("no \"secret\" field in the JSON".into()))?;
        let secret = parse_scalar(raw)?;
        return Ok(ParsedBackup {
            secret,
            address: map
                .get("address")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            origin: map
                .get("origin")
                .and_then(|v| v.as_str())
                .and_then(SecretOrigin::from_tag),
        });
    }

    Ok(ParsedBackup {
        secret: parse_scalar(trimmed)?,
        address: None,
        origin: None,
    })
}

/// Abbreviate an address for a warning message (`0x1234...abcd`).
///
/// Local to this module rather than shared with the header's `shorten`,
/// because this one is about *warning text* and must never panic on a
/// malformed address pasted out of a backup file.
pub fn short_address(address: &str) -> String {
    let chars: Vec<char> = address.chars().collect();
    if chars.len() <= 10 {
        return address.to_string();
    }
    let head: String = chars[..6].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}...{tail}")
}

/// Parse a bare decimal or `0x`-hex field element.
fn parse_scalar(raw: &str) -> Result<U256, SecretError> {
    let raw = raw.trim();
    let parsed = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        U256::from_str_radix(hex, 16)
    } else {
        U256::from_str_radix(raw, 10)
    }
    .map_err(|_| SecretError::BadBackup("not a decimal or 0x-hex number".into()))?;

    if parsed == U256::ZERO {
        return Err(SecretError::Zero);
    }
    if !viche_core::field::is_in_field(&parsed) {
        return Err(SecretError::OutOfField);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Everything in this module is pure: no `window`, no wallet, no storage.
    // The browser-dependent half lives in `wasm_tests` below.

    #[test]
    fn derivation_message_is_pure_ascii_and_version_tagged() {
        // A non-ASCII byte sneaking in (a smart quote from an editor, say)
        // would change every existing voter's secret on the next deploy.
        assert!(
            DERIVATION_MESSAGE_V1.is_ascii(),
            "the signed message must stay ASCII-only"
        );
        assert!(DERIVATION_MESSAGE_V1.contains("Version: 1"));
        assert!(DERIVATION_MESSAGE_V1.contains("Viche"));
        // Poll-independent: nothing poll- or time-specific may appear.
        assert!(!DERIVATION_MESSAGE_V1.to_lowercase().contains("poll id"));
    }

    #[test]
    fn derivation_is_deterministic_for_the_same_signature() {
        let sig = [0x11u8; 65];
        assert_eq!(
            derive_from_signature(&sig).unwrap(),
            derive_from_signature(&sig).unwrap()
        );
    }

    #[test]
    fn derivation_ignores_the_recovery_byte() {
        // Same r||s, different `v` encodings (0x1b vs 0x00) must agree, or a
        // voter changing wallet software would lose their identity.
        let mut a = [0x22u8; 65];
        let mut b = [0x22u8; 65];
        a[64] = 0x1b;
        b[64] = 0x00;
        assert_eq!(
            derive_from_signature(&a).unwrap(),
            derive_from_signature(&b).unwrap()
        );
    }

    #[test]
    fn derivation_differs_for_different_signatures() {
        let a = derive_from_signature(&[0x01u8; 65]).unwrap();
        let b = derive_from_signature(&[0x02u8; 65]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derivation_output_is_always_in_the_field() {
        for byte in [0x00u8, 0x7f, 0xaa, 0xff] {
            let s = derive_from_signature(&[byte; 65]).unwrap();
            assert!(viche_core::field::is_in_field(&s), "byte {byte:#x} escaped the field");
        }
    }

    #[test]
    fn derivation_rejects_a_truncated_signature() {
        let err = derive_from_signature(&[0u8; 32]).unwrap_err();
        assert!(matches!(err, SecretError::SigningFailed(_)));
    }

    #[test]
    fn origin_tags_round_trip() {
        for origin in [
            SecretOrigin::WalletDerivedV1,
            SecretOrigin::LegacyRandom,
            SecretOrigin::Imported,
        ] {
            assert_eq!(SecretOrigin::from_tag(origin.tag()), Some(origin));
        }
        assert_eq!(SecretOrigin::from_tag("something-else"), None);
    }

    #[test]
    fn only_wallet_derived_is_recoverable() {
        assert!(SecretOrigin::WalletDerivedV1.is_recoverable_from_wallet());
        assert!(!SecretOrigin::LegacyRandom.is_recoverable_from_wallet());
        assert!(!SecretOrigin::Imported.is_recoverable_from_wallet());
    }

    #[test]
    fn backup_blob_round_trips_through_parse_backup() {
        let secret = VoterSecret {
            value: U256::from(123_456_789u64),
            origin: SecretOrigin::WalletDerivedV1,
            storage_warning: None,
        };
        let blob = backup_blob("0xVoter", &secret);
        let parsed = parse_backup(&blob).unwrap();
        assert_eq!(parsed.secret, secret.value);
        assert_eq!(parsed.address.as_deref(), Some("0xVoter"));
        assert_eq!(parsed.origin, Some(SecretOrigin::WalletDerivedV1));
    }

    #[test]
    fn parse_backup_accepts_a_bare_decimal_value() {
        let parsed = parse_backup("  42  ").unwrap();
        assert_eq!(parsed.secret, U256::from(42u64));
        assert!(parsed.address.is_none());
    }

    #[test]
    fn parse_backup_accepts_a_bare_hex_value() {
        assert_eq!(parse_backup("0xff").unwrap().secret, U256::from(255u64));
        assert_eq!(parse_backup("0XFF").unwrap().secret, U256::from(255u64));
    }

    #[test]
    fn parse_backup_rejects_empty_and_garbage_input() {
        assert!(matches!(
            parse_backup("   ").unwrap_err(),
            SecretError::BadBackup(_)
        ));
        assert!(matches!(
            parse_backup("hello").unwrap_err(),
            SecretError::BadBackup(_)
        ));
    }

    #[test]
    fn parse_backup_rejects_json_without_a_secret_field() {
        let err = parse_backup(r#"{"viche_backup":1,"address":"0xa"}"#).unwrap_err();
        assert!(matches!(err, SecretError::BadBackup(_)));
    }

    #[test]
    fn parse_backup_rejects_zero_and_out_of_field_values() {
        assert!(matches!(parse_backup("0").unwrap_err(), SecretError::Zero));

        // The modulus itself is the first value outside the field. Reducing
        // it would yield zero and look like a successful import.
        let modulus = viche_core::field::MODULUS.to_string();
        assert!(matches!(
            parse_backup(&modulus).unwrap_err(),
            SecretError::OutOfField
        ));
    }

    #[test]
    fn storage_keys_keep_the_pre_existing_layout() {
        // The migration path depends on this exact key. If it ever changes,
        // every already-registered voter is stranded.
        assert_eq!(secret_storage_key("0xabc"), "viche:secret:0xabc");
        assert_eq!(origin_storage_key("0xabc"), "viche:secret-origin:0xabc");
    }

    #[test]
    fn parse_stored_value_rejects_junk_zero_and_out_of_field() {
        assert_eq!(parse_stored_value(" 7 "), Some(U256::from(7u64)));
        assert_eq!(parse_stored_value("not-a-number"), None);
        assert_eq!(parse_stored_value("0"), None);
        assert_eq!(parse_stored_value(&viche_core::field::MODULUS.to_string()), None);
    }

    #[test]
    fn short_address_never_panics_on_odd_input() {
        assert_eq!(short_address("0x1234567890abcdef1234"), "0x1234...1234");
        assert_eq!(short_address("0xabcd"), "0xabcd");
        assert_eq!(short_address(""), "");
        // Multibyte input would panic under byte slicing.
        assert_eq!(short_address("\u{00e9}".repeat(12).as_str()).chars().count(), 13);
    }

    #[test]
    fn every_error_has_an_actionable_message() {
        let errors = [
            SecretError::NoWallet,
            SecretError::SigningFailed("user rejected".into()),
            SecretError::BadBackup("nope".into()),
            SecretError::OutOfField,
            SecretError::Zero,
        ];
        for e in errors {
            assert!(e.user_message().len() > 40, "too terse: {}", e.user_message());
        }
    }
}

#[cfg(test)]
mod wasm_tests {
    use super::*;
    use crate::test_support::*;
    use wasm_bindgen_test::*;

    // `run_in_browser` is declared once, crate-wide, in `test_support`.

    /// A provider whose `personal_sign` returns a fixed signature, so
    /// derivation is reproducible inside a test.
    fn signing_mock(sig_byte: &str) -> String {
        format!(
            r#"if (method === "personal_sign") {{
                 return Promise.resolve("0x" + "{sig_byte}".repeat(65));
               }}
               return Promise.reject(new Error("unexpected method: " + method));"#
        )
    }

    /// Remove both keys for `address`, ignoring failures.
    fn clear(address: &str) {
        let _ = forget(address);
    }

    #[wasm_bindgen_test]
    async fn resolve_derives_from_the_wallet_and_caches_the_result() {
        let _guard = lock_global_mocks().await;
        let addr = "0xDERIVE1";
        clear(addr);
        install_mock_ethereum(&signing_mock("3c"), true);

        let first = resolve(addr).await.unwrap();
        assert_eq!(first.origin, SecretOrigin::WalletDerivedV1);
        assert!(first.storage_warning.is_none());
        assert_eq!(first.value, derive_from_signature(&[0x3cu8; 65]).unwrap());

        // Cached now: a second call must not depend on the wallet at all.
        remove_mock_ethereum();
        let second = resolve(addr).await.unwrap();
        assert_eq!(second.value, first.value);
        assert_eq!(second.origin, SecretOrigin::WalletDerivedV1);

        clear(addr);
    }

    #[wasm_bindgen_test]
    async fn resolve_is_deterministic_across_a_cleared_cache() {
        // The headline property: clearing site data must not change the
        // identity, because the wallet regenerates it.
        let _guard = lock_global_mocks().await;
        let addr = "0xDERIVE2";
        clear(addr);
        install_mock_ethereum(&signing_mock("7a"), true);

        let before = resolve(addr).await.unwrap().value;
        clear(addr);
        let after = resolve(addr).await.unwrap().value;
        assert_eq!(before, after, "a cleared cache must not change the secret");

        remove_mock_ethereum();
        clear(addr);
    }

    #[wasm_bindgen_test]
    async fn resolve_keeps_a_pre_existing_random_secret_and_tags_it_legacy() {
        // Migration guarantee: a secret written by the old build is returned
        // untouched. Re-deriving would invalidate an existing commitment.
        let _guard = lock_global_mocks().await;
        let addr = "0xLEGACY1";
        clear(addr);
        crate::storage::set(
            crate::storage::WebStorage::Local,
            &secret_storage_key(addr),
            "987654321",
        )
        .unwrap();
        // A wallet that would derive something *different* if consulted.
        install_mock_ethereum(&signing_mock("11"), true);

        let resolved = resolve(addr).await.unwrap();
        assert_eq!(resolved.value, U256::from(987_654_321u64));
        assert_eq!(resolved.origin, SecretOrigin::LegacyRandom);
        assert!(!resolved.origin.is_recoverable_from_wallet());

        // The provenance tag is backfilled so the UI can warn about it.
        let tag = crate::storage::get(
            crate::storage::WebStorage::Local,
            &origin_storage_key(addr),
        )
        .unwrap();
        assert_eq!(tag.as_deref(), Some("legacy-random"));

        remove_mock_ethereum();
        clear(addr);
    }

    #[wasm_bindgen_test]
    async fn resolve_rederives_over_a_corrupt_cache_entry() {
        let _guard = lock_global_mocks().await;
        let addr = "0xCORRUPT1";
        clear(addr);
        crate::storage::set(
            crate::storage::WebStorage::Local,
            &secret_storage_key(addr),
            "not-a-number",
        )
        .unwrap();
        install_mock_ethereum(&signing_mock("5d"), true);

        let resolved = resolve(addr).await.unwrap();
        assert_eq!(resolved.value, derive_from_signature(&[0x5du8; 65]).unwrap());
        assert_eq!(resolved.origin, SecretOrigin::WalletDerivedV1);

        remove_mock_ethereum();
        clear(addr);
    }

    #[wasm_bindgen_test]
    async fn resolve_surfaces_a_rejected_signature_instead_of_inventing_a_secret() {
        // The old code could never fail here: it generated randomness. That
        // is exactly the behaviour being removed - a refused signature must
        // be an error, not a brand-new unrecoverable identity.
        let _guard = lock_global_mocks().await;
        let addr = "0xREJECT1";
        clear(addr);
        install_mock_ethereum(
            r#"return Promise.reject(new Error("User rejected the request."));"#,
            true,
        );

        let err = resolve(addr).await.unwrap_err();
        assert!(matches!(err, SecretError::SigningFailed(_)));
        assert!(err.user_message().contains("signature"));

        // Nothing was written.
        assert!(cached(addr).unwrap().is_none());

        remove_mock_ethereum();
        clear(addr);
    }

    #[wasm_bindgen_test]
    async fn resolve_reports_no_wallet() {
        let _guard = lock_global_mocks().await;
        let addr = "0xNOWALLET1";
        clear(addr);
        remove_mock_ethereum();

        let err = resolve(addr).await.unwrap_err();
        assert!(matches!(err, SecretError::NoWallet));
        clear(addr);
    }

    #[wasm_bindgen_test]
    async fn migrate_replaces_a_legacy_secret_only_when_asked() {
        let _guard = lock_global_mocks().await;
        let addr = "0xMIGRATE1";
        clear(addr);
        crate::storage::set(
            crate::storage::WebStorage::Local,
            &secret_storage_key(addr),
            "55555",
        )
        .unwrap();
        install_mock_ethereum(&signing_mock("9e"), true);

        // Resolving leaves it alone...
        assert_eq!(resolve(addr).await.unwrap().value, U256::from(55_555u64));

        // ...and only the explicit call changes it.
        let migrated = migrate_to_wallet_derived(addr).await.unwrap();
        assert_eq!(migrated.origin, SecretOrigin::WalletDerivedV1);
        assert_eq!(migrated.value, derive_from_signature(&[0x9eu8; 65]).unwrap());
        assert_eq!(resolve(addr).await.unwrap().value, migrated.value);

        remove_mock_ethereum();
        clear(addr);
    }

    #[wasm_bindgen_test]
    fn import_persists_a_restored_secret_and_tags_it() {
        let addr = "0xIMPORT1";
        clear(addr);

        let imported = import(addr, U256::from(4242u64)).unwrap();
        assert_eq!(imported.origin, SecretOrigin::Imported);

        let read_back = cached(addr).unwrap().unwrap();
        assert_eq!(read_back.value, U256::from(4242u64));
        assert_eq!(read_back.origin, SecretOrigin::Imported);

        clear(addr);
    }

    #[wasm_bindgen_test]
    fn import_rejects_zero_and_out_of_field_values_without_writing() {
        let addr = "0xIMPORT2";
        clear(addr);

        assert!(matches!(
            import(addr, U256::ZERO).unwrap_err(),
            SecretError::Zero
        ));
        assert!(matches!(
            import(addr, viche_core::field::MODULUS).unwrap_err(),
            SecretError::OutOfField
        ));
        assert!(cached(addr).unwrap().is_none(), "a rejected import must not write");

        clear(addr);
    }

    #[wasm_bindgen_test]
    fn forget_removes_both_the_value_and_its_tag() {
        let addr = "0xFORGET1";
        import(addr, U256::from(7u64)).unwrap();
        assert!(cached(addr).unwrap().is_some());

        forget(addr).unwrap();
        assert!(cached(addr).unwrap().is_none());
        assert_eq!(
            crate::storage::get(
                crate::storage::WebStorage::Local,
                &origin_storage_key(addr)
            )
            .unwrap(),
            None
        );
    }

    #[wasm_bindgen_test]
    fn an_exported_backup_can_be_imported_into_a_second_account() {
        // The device-transfer story, end to end: export from one account,
        // paste into another browser/account, get the same identity back.
        let from = "0xEXPORTFROM";
        let to = "0xEXPORTTO";
        clear(from);
        clear(to);

        let original = import(from, U256::from(31_337u64)).unwrap();
        let blob = backup_blob(from, &original);

        let parsed = parse_backup(&blob).unwrap();
        assert_eq!(parsed.address.as_deref(), Some(from));
        let restored = import(to, parsed.secret).unwrap();
        assert_eq!(restored.value, original.value);

        clear(from);
        clear(to);
    }
}
