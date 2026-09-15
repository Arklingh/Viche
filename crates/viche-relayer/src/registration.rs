//! Persistent store for pre-poll voter registration.
//!
//! `VotingManager` has no way to add members to a poll's whitelist after
//! `createPoll` — the Merkle root is fixed at creation time. So voters need
//! somewhere to submit their identity commitment *before* the admin creates
//! the next poll, and the admin needs a way to later hand each voter back
//! the leaf list needed to build their own membership proof.
//!
//! # Security model (corrected)
//!
//! An earlier version of this module asserted that `POST /api/register` was
//! "safe to leave open" because a commitment is a one-way hash and the admin
//! decides what becomes a whitelist. **The first half is true; the
//! conclusion was wrong.** Confidentiality was never the threat here —
//! *Sybil capture* is. Dedup was exact-match on the `U256`, so an attacker
//! submitting 10,000 distinct commitments (each a hash of a secret only they
//! know) costs nothing, looks exactly like 10,000 honest voters, and if that
//! batch is snapshotted and published they control the entire electorate.
//! "The admin decides" was doing all the security work while nothing in code
//! gave the admin either a reason or the information to decide carefully.
//!
//! The endpoint is now gated by four mechanisms, none of which is a policy —
//! the deployer supplies the policy:
//!
//! 1. **Eligibility gate** — every submission passes
//!    [`crate::eligibility::EligibilityPolicy`] *before* anything is
//!    persisted. Default: invite codes with per-code use caps. See that
//!    module for how to plug in a real eligibility source.
//! 2. **Per-source cap** (`REGISTRATION_MAX_PER_SOURCE`, default 5) and
//!    **global batch cap** (`REGISTRATION_MAX_PENDING`, default 10,000), so
//!    a single actor cannot fill a batch even if the gate is `open`.
//! 3. **Rate limiting** on the endpoint, applied in [`crate::middleware`].
//! 4. **Explicit admin approval** (`REGISTRATION_REQUIRE_APPROVAL`, default
//!    `true`): a pending commitment does not flow into a snapshot until the
//!    admin marks it approved. Every entry carries provenance — submission
//!    time, eligibility note, and a source id — so approval is an informed
//!    act rather than a blind one.
//!
//! ## Source ids are salted hashes, never IP addresses
//!
//! Enforcing a per-source cap needs to recognise repeat submitters, but
//! storing raw client IPs next to identity commitments would create exactly
//! the kind of durable linkage record this system exists to avoid. So the
//! store keeps `keccak256(salt || ip)`, truncated to 8 bytes and hex-encoded.
//! The salt is 32 random bytes generated on first use and persisted
//! alongside the data, so ids stay stable across restarts (the cap survives
//! a reboot) while the file itself reveals nothing about who registered —
//! and, because the salt is not derived from anything guessable, an
//! attacker who obtains the file cannot confirm a suspected IP without also
//! obtaining the salt.
//!
//! What an admin sees is therefore an opaque but *clusterable* id: "40 of
//! these 50 registrations came from one source" is visible, "they came from
//! 203.0.113.9" is not.
//!
//! ## Crash safety
//!
//! The file is written to a temporary sibling, flushed, then renamed over
//! the target — `rename(2)` is atomic on POSIX and `MoveFileEx` with
//! `REPLACE_EXISTING` on Windows, so a crash mid-write leaves either the old
//! file or the new one, never a truncated hybrid. A persist failure is
//! surfaced to the caller (the request fails) instead of being logged and
//! forgotten: a registration the voter was told succeeded, but which is not
//! on disk, is worse than an error they can retry.
//!
//! A file that exists but does not parse is treated as **fatal**. The
//! previous behaviour — fall back to `Default` — meant a corrupt file
//! silently wiped the whole registry, turning a recoverable problem into an
//! unrecoverable one. The store now backs the bad file up and refuses to
//! start, so an operator notices while the data still exists.
//!
//! ## Why the relayer never hashes anything
//!
//! Building the Merkle tree from a commitment list requires Poseidon, and
//! today only the browser has a Poseidon implementation (via the
//! `circomlibjs` WASM bridge — see `viche-frontend::crypto`). Rather than
//! stand up a second, native Poseidon implementation on the relayer (real
//! crypto work, and any parameter mismatch with circomlib silently breaks
//! every proof — see `docs/crypto.md`'s "Gotcha #2"), the relayer only ever
//! stores and serves raw commitment lists. The admin's own browser builds
//! the tree and computes the root; voters' browsers rebuild the identical
//! tree from the same list to extract their own path. (Keccak, used for
//! source ids above, is *not* Poseidon and never touches a circuit input —
//! it is only ever used to anonymise a network address.)
//!
//! ## Flow
//!
//! 1. Voters `POST /api/register { commitment }` (plus `X-Invite-Code` under
//!    the default policy). Accepted submissions accumulate in `pending`,
//!    each with provenance.
//! 2. The admin reviews `GET /api/admin/registrations/pending?detailed=true`
//!    and approves what they accept via
//!    `POST /api/admin/registrations/approve`.
//! 3. The admin calls `POST /api/admin/registrations/snapshot`, which
//!    atomically drains the *approved* entries into `last_snapshot` and
//!    returns them — anything unapproved stays pending for the next batch,
//!    as do registrations arriving after this point.
//! 4. The admin's browser builds a `SparseMerkleTree` from the returned
//!    commitments and computes its root.
//! 5. The admin calls `POST /api/admin/registrations/publish { merkle_root }`,
//!    which stores `last_snapshot` under that root in `snapshots`.
//! 6. The admin creates the poll (via their wallet or the relayer's admin
//!    endpoint) using that same root — unrelated to this module, and not
//!    required to happen in any particular order relative to step 5.
//! 7. Any voter fetches `GET /api/polls/:id/registrations`, which looks up
//!    the poll's on-chain `merkle_root` and returns `snapshots[merkle_root]`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{keccak256, U256};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::RegistrationConfig;
use crate::error::RelayError;

/// Length of the persisted source-id salt, in bytes.
const SALT_LEN: usize = 32;

/// Bytes of the keccak digest kept for a source id. 8 bytes (16 hex chars)
/// is far past the point where collisions matter for a per-source cap, and
/// short enough to eyeball in an admin review list.
const SOURCE_ID_BYTES: usize = 8;

// =========================================================================
// Data model
// =========================================================================

/// One pending registration, with the provenance the admin reviews.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationEntry {
    /// `Poseidon(secret)` — the voter's identity commitment.
    pub commitment: U256,
    /// Unix seconds at which the relayer accepted this submission.
    pub submitted_at: u64,
    /// Salted, truncated hash of the submitting client IP. Opaque, but
    /// stable — repeated submissions from one network source share an id,
    /// which is what makes a Sybil cluster visible in review.
    pub source_id: String,
    /// The eligibility policy's provenance note, e.g. `invite-code:spring`.
    pub eligibility: String,
    /// Whether the admin has approved this entry for inclusion in a batch.
    pub approved: bool,
}

/// A stored entry, tolerating the pre-provenance file format.
///
/// The original file held bare `U256` commitments. Rather than treat an
/// older file as corrupt (and refuse to start, per the crash-safety rules
/// above), those are read as unapproved entries with unknown provenance —
/// which is exactly what they are, and which correctly forces the admin to
/// look at them before the next snapshot.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StoredEntry {
    Full(RegistrationEntry),
    Legacy(U256),
}

impl From<StoredEntry> for RegistrationEntry {
    fn from(e: StoredEntry) -> Self {
        match e {
            StoredEntry::Full(entry) => entry,
            StoredEntry::Legacy(commitment) => RegistrationEntry {
                commitment,
                submitted_at: 0,
                source_id: "unknown".into(),
                eligibility: "legacy:pre-provenance".into(),
                approved: false,
            },
        }
    }
}

/// On-disk representation. `snapshots` is a `Vec` (not the in-memory
/// `HashMap`) purely because `U256` isn't a valid JSON object key.
#[derive(Debug, Default, Deserialize)]
struct RegistrationFile {
    /// Hex-encoded salt for [`RegistrationEntry::source_id`]. Absent in
    /// files written before provenance existed; regenerated on first write.
    #[serde(default)]
    source_salt: String,
    #[serde(default)]
    pending: Vec<StoredEntry>,
    #[serde(default)]
    last_snapshot: Vec<U256>,
    #[serde(default)]
    snapshots: Vec<SnapshotEntry>,
}

/// Serialisable mirror of [`RegistrationFile`] used for writing (the read
/// side needs [`StoredEntry`]'s legacy tolerance; the write side never
/// emits the legacy form).
#[derive(Debug, Serialize)]
struct RegistrationFileOut<'a> {
    source_salt: String,
    pending: &'a [RegistrationEntry],
    last_snapshot: &'a [U256],
    snapshots: Vec<SnapshotEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotEntry {
    merkle_root: U256,
    commitments: Vec<U256>,
}

struct Inner {
    pending: Vec<RegistrationEntry>,
    last_snapshot: Vec<U256>,
    snapshots: HashMap<U256, Vec<U256>>,
}

/// Summary of the pending batch, for the admin review endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingSummary {
    /// Every pending entry, in submission order, with provenance.
    pub entries: Vec<RegistrationEntry>,
    /// How many are approved (i.e. would be included by `snapshot`).
    pub approved: usize,
    /// How many are still awaiting review.
    pub unapproved: usize,
    /// Whether approval is required at all for this deployment.
    pub approval_required: bool,
    /// Source ids contributing more than one registration, worst first —
    /// the cheapest signal of a Sybil cluster in a batch.
    pub source_clusters: Vec<SourceCluster>,
}

/// One source id and how many pending registrations it accounts for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceCluster {
    /// The opaque source id.
    pub source_id: String,
    /// Number of pending registrations attributed to it.
    pub count: usize,
}

// =========================================================================
// Store
// =========================================================================

/// The voter-registration store. Wrap in an `Arc` at construction and share
/// across Axum handlers.
pub struct RegistrationStore {
    path: PathBuf,
    source_salt: [u8; SALT_LEN],
    max_per_source: usize,
    max_pending: usize,
    require_approval: bool,
    inner: Mutex<Inner>,
}

/// Hand-written rather than derived so the source-id salt can never be
/// printed. A salt in a log line would let anyone holding the registration
/// file confirm a suspected IP, which is exactly what salting it prevents.
impl std::fmt::Debug for RegistrationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationStore")
            .field("path", &self.path)
            .field("source_salt", &"<redacted>")
            .field("max_per_source", &self.max_per_source)
            .field("max_pending", &self.max_pending)
            .field("require_approval", &self.require_approval)
            .finish_non_exhaustive()
    }
}

impl RegistrationStore {
    /// Load the store from `path`, applying the caps and approval policy in
    /// `cfg`.
    ///
    /// # Errors
    ///
    /// - The file exists but cannot be read (permissions, IO).
    /// - The file exists but does not parse. The bad file is first copied
    ///   aside to `<path>.corrupt.<unix-seconds>` so no data is lost, then
    ///   the error is returned — the caller is expected to abort startup.
    ///   Starting empty here would silently wipe the registry.
    pub async fn load(path: PathBuf, cfg: &RegistrationConfig) -> Result<Self, StoreError> {
        let file = match tokio::fs::read(&path).await {
            Ok(bytes) => match serde_json::from_slice::<RegistrationFile>(&bytes) {
                Ok(file) => file,
                Err(source) => {
                    let backup = backup_path(&path);
                    let backup_display = backup.display().to_string();
                    if let Err(e) = tokio::fs::write(&backup, &bytes).await {
                        tracing::error!(
                            error = %e,
                            backup = %backup_display,
                            "could not back up the corrupt registration file"
                        );
                    }
                    return Err(StoreError::Corrupt {
                        path: path.display().to_string(),
                        backup: backup_display,
                        source,
                    });
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => RegistrationFile::default(),
            Err(source) => {
                return Err(StoreError::Read {
                    path: path.display().to_string(),
                    source,
                })
            }
        };

        let source_salt = decode_salt(&file.source_salt).unwrap_or_else(random_salt);

        let snapshots = file
            .snapshots
            .into_iter()
            .map(|e| (e.merkle_root, e.commitments))
            .collect();
        let pending: Vec<RegistrationEntry> =
            file.pending.into_iter().map(RegistrationEntry::from).collect();

        Ok(Self {
            path,
            source_salt,
            max_per_source: cfg.max_per_source,
            max_pending: cfg.max_pending,
            require_approval: cfg.require_approval,
            inner: Mutex::new(Inner {
                pending,
                last_snapshot: file.last_snapshot,
                snapshots,
            }),
        })
    }

    /// Derive the opaque, salted source id for a client IP.
    ///
    /// The raw address is never stored, logged, or returned — only this.
    pub fn source_id(&self, ip: IpAddr) -> String {
        let mut buf = Vec::with_capacity(SALT_LEN + 16);
        buf.extend_from_slice(&self.source_salt);
        match ip {
            IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
        }
        let digest = keccak256(&buf);
        alloy_primitives::hex::encode(&digest[..SOURCE_ID_BYTES])
    }

    /// Record an eligible registration.
    ///
    /// The caller is responsible for having run the eligibility gate first
    /// and for passing its provenance note through as `eligibility`.
    ///
    /// # Errors
    ///
    /// - The commitment is already pending (exact duplicate).
    /// - `source_id` already accounts for `REGISTRATION_MAX_PER_SOURCE`
    ///   pending registrations.
    /// - The batch already holds `REGISTRATION_MAX_PENDING` entries.
    /// - The store could not be written to disk.
    pub async fn register(
        &self,
        commitment: U256,
        source_id: String,
        eligibility: String,
    ) -> Result<usize, RelayError> {
        let mut guard = self.inner.lock().await;

        if guard.pending.iter().any(|e| e.commitment == commitment) {
            return Err(RelayError::Validation(
                "this commitment is already registered".into(),
            ));
        }
        if guard.pending.len() >= self.max_pending {
            return Err(RelayError::RegistrationCapReached(format!(
                "the pending registration batch is full ({} entries); \
                 it must be snapshotted before more can be accepted",
                self.max_pending
            )));
        }

        let from_source = guard
            .pending
            .iter()
            .filter(|e| e.source_id == source_id)
            .count();
        if from_source >= self.max_per_source {
            // Deliberately does not say "per source" in terms the client can
            // use to work out what the key is; it just states the cap.
            return Err(RelayError::RegistrationCapReached(format!(
                "this network source has already submitted the maximum of {} \
                 registrations for the current batch",
                self.max_per_source
            )));
        }

        guard.pending.push(RegistrationEntry {
            commitment,
            submitted_at: now_secs(),
            source_id,
            eligibility,
            // Under an approval-required deployment this stays false until
            // the admin acts; otherwise entries are born approved so
            // `snapshot` behaves exactly as it did before.
            approved: !self.require_approval,
        });
        let total = guard.pending.len();
        self.persist(&guard).await?;
        Ok(total)
    }

    /// The commitments currently pending (not yet snapshotted), without
    /// provenance — the shape the existing admin UI consumes.
    pub async fn pending(&self) -> Vec<U256> {
        self.inner
            .lock()
            .await
            .pending
            .iter()
            .map(|e| e.commitment)
            .collect()
    }

    /// The pending batch with full provenance and cluster analysis.
    pub async fn pending_detailed(&self) -> PendingSummary {
        let guard = self.inner.lock().await;
        let approved = guard.pending.iter().filter(|e| e.approved).count();

        let mut counts: HashMap<&str, usize> = HashMap::new();
        for entry in &guard.pending {
            *counts.entry(entry.source_id.as_str()).or_insert(0) += 1;
        }
        let mut source_clusters: Vec<SourceCluster> = counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(source_id, count)| SourceCluster {
                source_id: source_id.to_string(),
                count,
            })
            .collect();
        source_clusters.sort_by(|a, b| b.count.cmp(&a.count).then(a.source_id.cmp(&b.source_id)));

        PendingSummary {
            entries: guard.pending.clone(),
            approved,
            unapproved: guard.pending.len() - approved,
            approval_required: self.require_approval,
            source_clusters,
        }
    }

    /// Mark specific pending commitments as approved.
    ///
    /// Returns `(newly_approved, unknown)` — commitments that were not in
    /// the pending batch are reported back rather than silently ignored, so
    /// a typo in an admin's list is visible.
    pub async fn approve(&self, commitments: &[U256]) -> Result<(usize, Vec<U256>), RelayError> {
        let mut guard = self.inner.lock().await;
        let mut approved = 0usize;
        let mut unknown = Vec::new();

        for c in commitments {
            match guard.pending.iter_mut().find(|e| e.commitment == *c) {
                Some(entry) => {
                    if !entry.approved {
                        entry.approved = true;
                        approved += 1;
                    }
                }
                None => unknown.push(*c),
            }
        }

        if approved > 0 {
            self.persist(&guard).await?;
        }
        Ok((approved, unknown))
    }

    /// Approve every currently-pending entry.
    ///
    /// Still an explicit admin act on an explicit batch — it is a shortcut
    /// for "I have reviewed this list", not a way to switch approval off.
    /// Returns the number newly approved.
    pub async fn approve_all(&self) -> Result<usize, RelayError> {
        let mut guard = self.inner.lock().await;
        let mut approved = 0usize;
        for entry in guard.pending.iter_mut() {
            if !entry.approved {
                entry.approved = true;
                approved += 1;
            }
        }
        if approved > 0 {
            self.persist(&guard).await?;
        }
        Ok(approved)
    }

    /// Discard specific pending commitments without approving them.
    ///
    /// The counterpart to [`Self::approve`]: an admin who spots a Sybil
    /// cluster in review needs a way to remove it, not just to leave it
    /// pending forever (where it would keep consuming the batch cap).
    /// Returns the number removed.
    pub async fn reject(&self, commitments: &[U256]) -> Result<usize, RelayError> {
        let mut guard = self.inner.lock().await;
        let before = guard.pending.len();
        guard
            .pending
            .retain(|e| !commitments.contains(&e.commitment));
        let removed = before - guard.pending.len();
        if removed > 0 {
            self.persist(&guard).await?;
        }
        Ok(removed)
    }

    /// Atomically drain the *approved* pending entries into `last_snapshot`
    /// and return their commitments. Unapproved entries and anything
    /// submitted after this call remain pending for the next batch.
    ///
    /// # Errors
    ///
    /// If approval is required and nothing in a non-empty batch has been
    /// approved, this errors rather than silently returning an empty list —
    /// an empty snapshot published as a Merkle root would produce a poll
    /// nobody can vote in.
    pub async fn snapshot(&self) -> Result<Vec<U256>, RelayError> {
        let mut guard = self.inner.lock().await;

        let approved_count = guard.pending.iter().filter(|e| e.approved).count();
        if approved_count == 0 && !guard.pending.is_empty() {
            return Err(RelayError::Validation(format!(
                "none of the {} pending registrations have been approved; \
                 review them at GET /api/admin/registrations/pending?detailed=true \
                 and approve via POST /api/admin/registrations/approve",
                guard.pending.len()
            )));
        }

        let mut taken = Vec::with_capacity(approved_count);
        let mut remaining = Vec::with_capacity(guard.pending.len() - approved_count);
        for entry in std::mem::take(&mut guard.pending) {
            if entry.approved {
                taken.push(entry.commitment);
            } else {
                remaining.push(entry);
            }
        }
        guard.pending = remaining;
        guard.last_snapshot = taken.clone();
        self.persist(&guard).await?;
        Ok(taken)
    }

    /// Store the most recent snapshot under `merkle_root`, once the admin's
    /// browser has computed it. Errors if `snapshot` was never called (or
    /// returned nothing to snapshot).
    pub async fn publish(&self, merkle_root: U256) -> Result<usize, RelayError> {
        let mut guard = self.inner.lock().await;
        if guard.last_snapshot.is_empty() {
            return Err(RelayError::Validation(
                "no pending snapshot to publish; call snapshot first".into(),
            ));
        }
        let commitments = guard.last_snapshot.clone();
        let count = commitments.len();
        guard.snapshots.insert(merkle_root, commitments);
        self.persist(&guard).await?;
        Ok(count)
    }

    /// Look up the commitment list published under `merkle_root`, if any.
    pub async fn for_root(&self, merkle_root: &U256) -> Option<Vec<U256>> {
        self.inner.lock().await.snapshots.get(merkle_root).cloned()
    }

    /// Write the store to disk atomically: serialise, write a temp sibling,
    /// flush it, then rename over the target.
    async fn persist(&self, guard: &Inner) -> Result<(), RelayError> {
        let file = RegistrationFileOut {
            source_salt: alloy_primitives::hex::encode(self.source_salt),
            pending: &guard.pending,
            last_snapshot: &guard.last_snapshot,
            snapshots: guard
                .snapshots
                .iter()
                .map(|(root, commitments)| SnapshotEntry {
                    merkle_root: *root,
                    commitments: commitments.clone(),
                })
                .collect(),
        };

        let bytes = serde_json::to_vec_pretty(&file)?;
        write_atomic(&self.path, &bytes).await.map_err(|e| {
            tracing::error!(
                error = %e,
                path = %self.path.display(),
                "failed to persist registration store"
            );
            RelayError::Persistence(e.to_string())
        })
    }
}

// =========================================================================
// Helpers
// =========================================================================

/// Write `bytes` to `path` such that a crash leaves either the previous
/// contents or the new ones — never a partial file.
///
/// The temp file carries the process id so two relayers pointed (by
/// mistake) at one path don't clobber each other's temp file mid-write.
async fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".tmp.{}", std::process::id()));
    let tmp = PathBuf::from(tmp);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }

    // Scope the handle so it is closed before the rename — Windows refuses
    // to replace a file that still has an open handle.
    {
        let mut f = tokio::fs::File::create(&tmp).await?;
        f.write_all(bytes).await?;
        // Durability, not just ordering: without the sync the rename can be
        // visible while the data blocks are not.
        f.sync_all().await?;
    }

    match tokio::fs::rename(&tmp, path).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            Err(e)
        }
    }
}

/// `<path>.corrupt.<unix-seconds>` — where a file that failed to parse is
/// preserved before the store refuses to start.
fn backup_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(format!(".corrupt.{}", now_secs()));
    PathBuf::from(p)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn decode_salt(hex_str: &str) -> Option<[u8; SALT_LEN]> {
    let bytes = alloy_primitives::hex::decode(hex_str).ok()?;
    bytes.try_into().ok()
}

/// 32 bytes of randomness for the source-id salt.
///
/// Sourced from `PrivateKeySigner::random`, which is already a dependency
/// and is backed by the OS CSPRNG — adding a `rand` dependency just for this
/// would be more moving parts than borrowing the one already present.
fn random_salt() -> [u8; SALT_LEN] {
    use alloy::signers::local::PrivateKeySigner;
    PrivateKeySigner::random().to_bytes().into()
}

/// Failures constructing a [`RegistrationStore`]. All are fatal at startup.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The registration file exists but could not be read.
    #[error("failed to read registration store {path}: {source}")]
    Read {
        /// The path that could not be read.
        path: String,
        /// The underlying IO error.
        source: std::io::Error,
    },
    /// The registration file exists but does not parse.
    #[error(
        "registration store {path} is corrupt and was NOT loaded ({source}). \
         A copy was saved to {backup}. Refusing to start with an empty registry — \
         repair or remove the file, then restart."
    )]
    Corrupt {
        /// The unparseable path.
        path: String,
        /// Where the bad file was copied.
        backup: String,
        /// The parse error.
        source: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn test_cfg() -> RegistrationConfig {
        use crate::config::EligibilityPolicyKind;
        RegistrationConfig {
            policy: EligibilityPolicyKind::Open,
            invite_codes: HashMap::new(),
            allowlist_file: None,
            require_approval: false,
            max_per_source: 100,
            max_pending: 1000,
        }
    }

    fn unique_path() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("viche-registrations-test-{nanos}-{n}.json"))
    }

    async fn store_with(cfg: RegistrationConfig) -> RegistrationStore {
        RegistrationStore::load(unique_path(), &cfg).await.unwrap()
    }

    async fn temp_store() -> RegistrationStore {
        store_with(test_cfg()).await
    }

    /// Register with throwaway provenance, for tests about other behaviour.
    async fn reg(store: &RegistrationStore, n: u64) -> Result<usize, RelayError> {
        store
            .register(U256::from(n), "src-1".into(), "test".into())
            .await
    }

    // ---- basic accumulation (behaviour preserved from before) -------------

    #[tokio::test]
    async fn register_accumulates_into_pending() {
        let store = temp_store().await;
        assert_eq!(reg(&store, 1).await.unwrap(), 1);
        assert_eq!(reg(&store, 2).await.unwrap(), 2);
        assert_eq!(
            store.pending().await,
            vec![U256::from(1u64), U256::from(2u64)]
        );
    }

    #[tokio::test]
    async fn register_rejects_exact_duplicate() {
        let store = temp_store().await;
        reg(&store, 1).await.unwrap();
        let err = reg(&store, 1).await.unwrap_err();
        assert!(matches!(err, RelayError::Validation(_)));
        assert_eq!(store.pending().await.len(), 1);
    }

    #[tokio::test]
    async fn snapshot_drains_pending_and_starts_a_fresh_batch() {
        let store = temp_store().await;
        reg(&store, 1).await.unwrap();
        reg(&store, 2).await.unwrap();

        let snap = store.snapshot().await.unwrap();
        assert_eq!(snap, vec![U256::from(1u64), U256::from(2u64)]);
        assert!(store.pending().await.is_empty());

        reg(&store, 3).await.unwrap();
        assert_eq!(store.pending().await, vec![U256::from(3u64)]);
    }

    #[tokio::test]
    async fn publish_stores_the_last_snapshot_under_the_given_root() {
        let store = temp_store().await;
        reg(&store, 1).await.unwrap();
        store.snapshot().await.unwrap();

        let root = U256::from(42u64);
        assert_eq!(store.publish(root).await.unwrap(), 1);
        assert_eq!(store.for_root(&root).await, Some(vec![U256::from(1u64)]));
    }

    #[tokio::test]
    async fn publish_without_a_snapshot_errors() {
        let store = temp_store().await;
        let err = store.publish(U256::from(42u64)).await.unwrap_err();
        assert!(matches!(err, RelayError::Validation(_)));
    }

    #[tokio::test]
    async fn for_root_returns_none_for_an_unknown_root() {
        let store = temp_store().await;
        assert_eq!(store.for_root(&U256::from(999u64)).await, None);
    }

    #[tokio::test]
    async fn snapshot_of_an_empty_batch_is_empty_not_an_error() {
        let store = store_with(RegistrationConfig {
            require_approval: true,
            ..test_cfg()
        })
        .await;
        assert!(store.snapshot().await.unwrap().is_empty());
    }

    // ---- caps ------------------------------------------------------------

    #[tokio::test]
    async fn per_source_cap_blocks_a_sybil_run_from_one_source() {
        let store = store_with(RegistrationConfig {
            max_per_source: 3,
            ..test_cfg()
        })
        .await;

        for n in 0..3 {
            store
                .register(U256::from(n), "attacker".into(), "open".into())
                .await
                .unwrap();
        }
        let err = store
            .register(U256::from(99u64), "attacker".into(), "open".into())
            .await
            .unwrap_err();
        assert!(matches!(err, RelayError::RegistrationCapReached(_)));

        // A different source is unaffected.
        store
            .register(U256::from(100u64), "honest".into(), "open".into())
            .await
            .unwrap();
        assert_eq!(store.pending().await.len(), 4);
    }

    #[tokio::test]
    async fn global_cap_blocks_the_batch_regardless_of_source() {
        let store = store_with(RegistrationConfig {
            max_pending: 2,
            ..test_cfg()
        })
        .await;

        store
            .register(U256::from(1u64), "a".into(), "open".into())
            .await
            .unwrap();
        store
            .register(U256::from(2u64), "b".into(), "open".into())
            .await
            .unwrap();
        let err = store
            .register(U256::from(3u64), "c".into(), "open".into())
            .await
            .unwrap_err();
        assert!(matches!(err, RelayError::RegistrationCapReached(_)));
    }

    #[tokio::test]
    async fn the_per_source_cap_frees_up_after_a_snapshot() {
        let store = store_with(RegistrationConfig {
            max_per_source: 1,
            ..test_cfg()
        })
        .await;
        store
            .register(U256::from(1u64), "a".into(), "open".into())
            .await
            .unwrap();
        assert!(store
            .register(U256::from(2u64), "a".into(), "open".into())
            .await
            .is_err());

        store.snapshot().await.unwrap();
        store
            .register(U256::from(2u64), "a".into(), "open".into())
            .await
            .unwrap();
    }

    // ---- approval --------------------------------------------------------

    fn approval_cfg() -> RegistrationConfig {
        RegistrationConfig {
            require_approval: true,
            ..test_cfg()
        }
    }

    #[tokio::test]
    async fn entries_are_unapproved_when_approval_is_required() {
        let store = store_with(approval_cfg()).await;
        reg(&store, 1).await.unwrap();
        let summary = store.pending_detailed().await;
        assert_eq!(summary.approved, 0);
        assert_eq!(summary.unapproved, 1);
        assert!(summary.approval_required);
        assert!(!summary.entries[0].approved);
    }

    #[tokio::test]
    async fn entries_are_born_approved_when_approval_is_not_required() {
        let store = temp_store().await;
        reg(&store, 1).await.unwrap();
        let summary = store.pending_detailed().await;
        assert_eq!(summary.approved, 1);
        assert!(!summary.approval_required);
    }

    #[tokio::test]
    async fn snapshot_refuses_a_batch_with_nothing_approved() {
        let store = store_with(approval_cfg()).await;
        reg(&store, 1).await.unwrap();
        let err = store.snapshot().await.unwrap_err();
        assert!(matches!(err, RelayError::Validation(_)));
        // Nothing was consumed.
        assert_eq!(store.pending().await.len(), 1);
    }

    #[tokio::test]
    async fn snapshot_takes_only_approved_entries_and_leaves_the_rest() {
        let store = store_with(approval_cfg()).await;
        reg(&store, 1).await.unwrap();
        reg(&store, 2).await.unwrap();
        reg(&store, 3).await.unwrap();

        let (approved, unknown) = store
            .approve(&[U256::from(1u64), U256::from(3u64)])
            .await
            .unwrap();
        assert_eq!(approved, 2);
        assert!(unknown.is_empty());

        let snap = store.snapshot().await.unwrap();
        assert_eq!(snap, vec![U256::from(1u64), U256::from(3u64)]);
        assert_eq!(store.pending().await, vec![U256::from(2u64)]);
    }

    #[tokio::test]
    async fn approve_reports_unknown_commitments_instead_of_ignoring_them() {
        let store = store_with(approval_cfg()).await;
        reg(&store, 1).await.unwrap();
        let (approved, unknown) = store
            .approve(&[U256::from(1u64), U256::from(777u64)])
            .await
            .unwrap();
        assert_eq!(approved, 1);
        assert_eq!(unknown, vec![U256::from(777u64)]);
    }

    #[tokio::test]
    async fn approving_twice_counts_once() {
        let store = store_with(approval_cfg()).await;
        reg(&store, 1).await.unwrap();
        assert_eq!(store.approve(&[U256::from(1u64)]).await.unwrap().0, 1);
        assert_eq!(store.approve(&[U256::from(1u64)]).await.unwrap().0, 0);
    }

    #[tokio::test]
    async fn approve_all_approves_the_whole_batch() {
        let store = store_with(approval_cfg()).await;
        for n in 1..=4 {
            reg(&store, n).await.unwrap();
        }
        assert_eq!(store.approve_all().await.unwrap(), 4);
        assert_eq!(store.approve_all().await.unwrap(), 0);
        assert_eq!(store.snapshot().await.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn reject_removes_entries_from_the_batch() {
        let store = store_with(approval_cfg()).await;
        reg(&store, 1).await.unwrap();
        reg(&store, 2).await.unwrap();
        assert_eq!(store.reject(&[U256::from(1u64)]).await.unwrap(), 1);
        assert_eq!(store.pending().await, vec![U256::from(2u64)]);
        // Rejecting something absent is a no-op, not an error.
        assert_eq!(store.reject(&[U256::from(1u64)]).await.unwrap(), 0);
    }

    // ---- provenance ------------------------------------------------------

    #[tokio::test]
    async fn entries_record_their_eligibility_note_and_source() {
        let store = temp_store().await;
        store
            .register(
                U256::from(5u64),
                "src-xyz".into(),
                "invite-code:spring".into(),
            )
            .await
            .unwrap();
        let summary = store.pending_detailed().await;
        let entry = &summary.entries[0];
        assert_eq!(entry.source_id, "src-xyz");
        assert_eq!(entry.eligibility, "invite-code:spring");
        assert!(entry.submitted_at > 0);
    }

    #[tokio::test]
    async fn pending_detailed_surfaces_source_clusters_worst_first() {
        let store = temp_store().await;
        for n in 0..4u64 {
            store
                .register(U256::from(n), "cluster-a".into(), "open".into())
                .await
                .unwrap();
        }
        for n in 10..12u64 {
            store
                .register(U256::from(n), "cluster-b".into(), "open".into())
                .await
                .unwrap();
        }
        store
            .register(U256::from(99u64), "lone".into(), "open".into())
            .await
            .unwrap();

        let summary = store.pending_detailed().await;
        assert_eq!(summary.source_clusters.len(), 2, "singletons are not clusters");
        assert_eq!(summary.source_clusters[0].source_id, "cluster-a");
        assert_eq!(summary.source_clusters[0].count, 4);
        assert_eq!(summary.source_clusters[1].count, 2);
    }

    // ---- source ids ------------------------------------------------------

    #[tokio::test]
    async fn source_ids_are_stable_per_ip_and_differ_between_ips() {
        let store = temp_store().await;
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        assert_eq!(store.source_id(a), store.source_id(a));
        assert_ne!(store.source_id(a), store.source_id(b));
        assert_eq!(store.source_id(a).len(), SOURCE_ID_BYTES * 2);
    }

    #[tokio::test]
    async fn a_source_id_does_not_contain_the_raw_address() {
        let store = temp_store().await;
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        assert!(!store.source_id(ip).contains("203"));
    }

    #[tokio::test]
    async fn source_ids_survive_a_restart_because_the_salt_is_persisted() {
        let path = unique_path();
        let cfg = test_cfg();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));

        let store = RegistrationStore::load(path.clone(), &cfg).await.unwrap();
        let before = store.source_id(ip);
        reg(&store, 1).await.unwrap(); // forces a persist, writing the salt

        let reloaded = RegistrationStore::load(path.clone(), &cfg).await.unwrap();
        assert_eq!(reloaded.source_id(ip), before);

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn two_stores_with_independent_salts_produce_different_ids() {
        let a = temp_store().await;
        let b = temp_store().await;
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));
        assert_ne!(a.source_id(ip), b.source_id(ip));
    }

    // ---- persistence -----------------------------------------------------

    #[tokio::test]
    async fn state_survives_a_reload_from_disk() {
        let path = unique_path();
        let cfg = test_cfg();

        let store = RegistrationStore::load(path.clone(), &cfg).await.unwrap();
        reg(&store, 7).await.unwrap();
        store.snapshot().await.unwrap();
        store.publish(U256::from(99u64)).await.unwrap();

        let reloaded = RegistrationStore::load(path.clone(), &cfg).await.unwrap();
        assert_eq!(
            reloaded.for_root(&U256::from(99u64)).await,
            Some(vec![U256::from(7u64)])
        );

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn provenance_and_approval_survive_a_reload() {
        let path = unique_path();
        let cfg = approval_cfg();

        let store = RegistrationStore::load(path.clone(), &cfg).await.unwrap();
        store
            .register(U256::from(1u64), "src-1".into(), "invite-code:x".into())
            .await
            .unwrap();
        store
            .register(U256::from(2u64), "src-2".into(), "invite-code:y".into())
            .await
            .unwrap();
        store.approve(&[U256::from(2u64)]).await.unwrap();

        let reloaded = RegistrationStore::load(path.clone(), &cfg).await.unwrap();
        let summary = reloaded.pending_detailed().await;
        assert_eq!(summary.approved, 1);
        assert_eq!(summary.unapproved, 1);
        assert_eq!(summary.entries[1].eligibility, "invite-code:y");
        assert!(summary.entries[1].approved);

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn no_temp_file_is_left_behind_after_a_write() {
        let path = unique_path();
        let store = RegistrationStore::load(path.clone(), &test_cfg())
            .await
            .unwrap();
        reg(&store, 1).await.unwrap();

        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(format!(".tmp.{}", std::process::id()));
        assert!(!PathBuf::from(tmp).exists());
        assert!(path.exists());

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn a_missing_file_loads_as_an_empty_store() {
        let store = RegistrationStore::load(unique_path(), &test_cfg())
            .await
            .unwrap();
        assert!(store.pending().await.is_empty());
    }

    #[tokio::test]
    async fn a_corrupt_file_fails_loudly_and_is_backed_up() {
        let path = unique_path();
        tokio::fs::write(&path, b"{ this is not json").await.unwrap();

        let err = RegistrationStore::load(path.clone(), &test_cfg())
            .await
            .unwrap_err();
        let backup = match &err {
            StoreError::Corrupt { backup, .. } => PathBuf::from(backup),
            other => panic!("expected Corrupt, got {other:?}"),
        };
        assert!(backup.exists(), "the corrupt file must be preserved");
        assert_eq!(
            tokio::fs::read(&backup).await.unwrap(),
            b"{ this is not json"
        );
        // The original is untouched — nothing was silently wiped.
        assert!(path.exists());

        let _ = tokio::fs::remove_file(&path).await;
        let _ = tokio::fs::remove_file(&backup).await;
    }

    #[tokio::test]
    async fn a_semantically_wrong_but_valid_json_file_also_fails_loudly() {
        let path = unique_path();
        tokio::fs::write(&path, br#"{"pending": "not-a-list"}"#)
            .await
            .unwrap();
        assert!(matches!(
            RegistrationStore::load(path.clone(), &test_cfg())
                .await
                .unwrap_err(),
            StoreError::Corrupt { .. }
        ));
        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn a_legacy_bare_commitment_file_still_loads() {
        // Files written before provenance existed must upgrade, not trip
        // the corrupt-file guard.
        let path = unique_path();
        tokio::fs::write(
            &path,
            br#"{"pending":[1,2],"last_snapshot":[],"snapshots":[]}"#,
        )
        .await
        .unwrap();

        let store = RegistrationStore::load(path.clone(), &approval_cfg())
            .await
            .unwrap();
        assert_eq!(
            store.pending().await,
            vec![U256::from(1u64), U256::from(2u64)]
        );
        let summary = store.pending_detailed().await;
        // Migrated entries are unapproved: the admin must look at them.
        assert_eq!(summary.unapproved, 2);
        assert_eq!(summary.entries[0].eligibility, "legacy:pre-provenance");

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn persist_creates_missing_parent_directories() {
        let dir = std::env::temp_dir().join(format!("viche-reg-dir-{}", now_secs()));
        let path = dir.join("nested").join("registrations.json");
        let store = RegistrationStore::load(path.clone(), &test_cfg())
            .await
            .unwrap();
        reg(&store, 1).await.unwrap();
        assert!(path.exists());
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
