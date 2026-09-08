//! Persistent store for pre-poll voter registration.
//!
//! `VotingManager` has no way to add members to a poll's whitelist after
//! `createPoll` — the Merkle root is fixed at creation time. So voters need
//! somewhere to submit their identity commitment *before* the admin creates
//! the next poll, and the admin needs a way to later hand each voter back
//! the leaf list needed to build their own membership proof.
//!
//! This is a deliberate, minimal exception to the relayer's usual
//! stateless-proxy design (see `crate` docs): it holds one small JSON file
//! on disk, guarded by a mutex, rewritten on every mutation. Nothing stored
//! here is secret — commitments are one-way hashes (`Poseidon(secret)`),
//! and a Merkle root is already public once its poll exists on-chain — so
//! losing or corrupting this file only loses convenience (voters would need
//! to re-register), never security.
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
//! tree from the same list to extract their own path. This reuses the
//! already-proven frontend Merkle code end to end.
//!
//! ## Flow
//!
//! 1. Voters `POST /api/register { commitment }` any time before the admin
//!    closes registration (accumulates in `pending`).
//! 2. The admin calls `POST /api/admin/registrations/snapshot`, which
//!    atomically drains `pending` into `last_snapshot` and returns it — any
//!    registrations that arrive after this point start accumulating fresh
//!    in `pending`, for the *next* poll, rather than mixing into this batch.
//! 3. The admin's browser builds a `SparseMerkleTree` from the returned
//!    commitments and computes its root.
//! 4. The admin calls `POST /api/admin/registrations/publish { merkle_root }`,
//!    which stores `last_snapshot` under that root in `snapshots`.
//! 5. The admin creates the poll (via their wallet or the relayer's admin
//!    endpoint) using that same root — unrelated to this module, and not
//!    required to happen in any particular order relative to step 4.
//! 6. Any voter fetches `GET /api/polls/:id/registrations`, which looks up
//!    the poll's on-chain `merkle_root` and returns `snapshots[merkle_root]`.

use std::collections::HashMap;
use std::path::PathBuf;

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::error::RelayError;

/// On-disk representation. `snapshots` is a `Vec` (not the in-memory
/// `HashMap`) purely because `U256` isn't a valid JSON object key.
#[derive(Debug, Default, Serialize, Deserialize)]
struct RegistrationFile {
    pending: Vec<U256>,
    last_snapshot: Vec<U256>,
    snapshots: Vec<SnapshotEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotEntry {
    merkle_root: U256,
    commitments: Vec<U256>,
}

struct Inner {
    pending: Vec<U256>,
    last_snapshot: Vec<U256>,
    snapshots: HashMap<U256, Vec<U256>>,
}

/// The voter-registration store. Cheap to clone (wrap in `Arc` at
/// construction) and safe to share across Axum handlers.
pub struct RegistrationStore {
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl RegistrationStore {
    /// Load the store from `path`, or start empty if the file doesn't exist
    /// or fails to parse (treated as "fresh install", not a fatal error —
    /// this is convenience data, not the source of truth for anything
    /// on-chain).
    pub async fn load(path: PathBuf) -> Self {
        let file = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice::<RegistrationFile>(&bytes).unwrap_or_default(),
            Err(_) => RegistrationFile::default(),
        };
        let snapshots = file
            .snapshots
            .into_iter()
            .map(|e| (e.merkle_root, e.commitments))
            .collect();
        Self {
            path,
            inner: Mutex::new(Inner {
                pending: file.pending,
                last_snapshot: file.last_snapshot,
                snapshots,
            }),
        }
    }

    /// Add a commitment to the pending list. Rejects an exact duplicate
    /// (most likely a double-submitted form) so the pending list stays
    /// dedup'd; returns the new pending count either way isn't meaningful
    /// once rejected, so this returns an error instead.
    pub async fn register(&self, commitment: U256) -> Result<usize, RelayError> {
        let mut guard = self.inner.lock().await;
        if guard.pending.contains(&commitment) {
            return Err(RelayError::Validation(
                "this commitment is already registered".into(),
            ));
        }
        guard.pending.push(commitment);
        let total = guard.pending.len();
        self.persist(&guard).await;
        Ok(total)
    }

    /// The current pending list (not yet snapshotted).
    pub async fn pending(&self) -> Vec<U256> {
        self.inner.lock().await.pending.clone()
    }

    /// Atomically drain `pending` into `last_snapshot` and return it. Any
    /// registrations submitted after this call land in a fresh, empty
    /// `pending` rather than this batch.
    pub async fn snapshot(&self) -> Vec<U256> {
        let mut guard = self.inner.lock().await;
        let taken = std::mem::take(&mut guard.pending);
        guard.last_snapshot = taken.clone();
        self.persist(&guard).await;
        taken
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
        self.persist(&guard).await;
        Ok(count)
    }

    /// Look up the commitment list published under `merkle_root`, if any.
    pub async fn for_root(&self, merkle_root: &U256) -> Option<Vec<U256>> {
        self.inner.lock().await.snapshots.get(merkle_root).cloned()
    }

    async fn persist(&self, guard: &Inner) {
        let file = RegistrationFile {
            pending: guard.pending.clone(),
            last_snapshot: guard.last_snapshot.clone(),
            snapshots: guard
                .snapshots
                .iter()
                .map(|(root, commitments)| SnapshotEntry {
                    merkle_root: *root,
                    commitments: commitments.clone(),
                })
                .collect(),
        };
        match serde_json::to_vec_pretty(&file) {
            Ok(bytes) => {
                if let Err(e) = tokio::fs::write(&self.path, bytes).await {
                    tracing::warn!(
                        error = %e,
                        path = %self.path.display(),
                        "failed to persist registration store"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialise registration store");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn temp_store() -> RegistrationStore {
        let mut path = std::env::temp_dir();
        path.push(format!("viche-registrations-test-{}.json", uuid()));
        RegistrationStore::load(path).await
    }

    fn uuid() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[tokio::test]
    async fn register_accumulates_into_pending() {
        let store = temp_store().await;
        assert_eq!(store.register(U256::from(1u64)).await.unwrap(), 1);
        assert_eq!(store.register(U256::from(2u64)).await.unwrap(), 2);
        assert_eq!(store.pending().await, vec![U256::from(1u64), U256::from(2u64)]);
    }

    #[tokio::test]
    async fn register_rejects_exact_duplicate() {
        let store = temp_store().await;
        store.register(U256::from(1u64)).await.unwrap();
        let err = store.register(U256::from(1u64)).await.unwrap_err();
        assert!(matches!(err, RelayError::Validation(_)));
        assert_eq!(store.pending().await.len(), 1);
    }

    #[tokio::test]
    async fn snapshot_drains_pending_and_starts_a_fresh_batch() {
        let store = temp_store().await;
        store.register(U256::from(1u64)).await.unwrap();
        store.register(U256::from(2u64)).await.unwrap();

        let snap = store.snapshot().await;
        assert_eq!(snap, vec![U256::from(1u64), U256::from(2u64)]);
        assert!(store.pending().await.is_empty());

        // Registrations after the snapshot land in the new, empty batch.
        store.register(U256::from(3u64)).await.unwrap();
        assert_eq!(store.pending().await, vec![U256::from(3u64)]);
    }

    #[tokio::test]
    async fn publish_stores_the_last_snapshot_under_the_given_root() {
        let store = temp_store().await;
        store.register(U256::from(1u64)).await.unwrap();
        store.snapshot().await;

        let root = U256::from(42u64);
        let count = store.publish(root).await.unwrap();
        assert_eq!(count, 1);
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
    async fn state_survives_a_reload_from_disk() {
        let mut path = std::env::temp_dir();
        path.push(format!("viche-registrations-test-{}.json", uuid()));

        let store = RegistrationStore::load(path.clone()).await;
        store.register(U256::from(7u64)).await.unwrap();
        store.snapshot().await;
        store.publish(U256::from(99u64)).await.unwrap();

        let reloaded = RegistrationStore::load(path.clone()).await;
        assert_eq!(
            reloaded.for_root(&U256::from(99u64)).await,
            Some(vec![U256::from(7u64)])
        );

        let _ = tokio::fs::remove_file(&path).await;
    }
}
