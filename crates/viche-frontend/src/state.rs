//! Global reactive state for the Viche SPA.
//!
//! Built on Leptos signals. The signals here are the single source of truth
//! for UI state; components read them reactively and write through typed
//! actions, keeping the view macros free of business logic.

use leptos::{RwSignal, SignalGet, SignalGetUntracked, SignalSet, SignalUpdate};
use viche_core::wire::{PollData, TallyResponse, VoteResponse};

use crate::secret::{SecretOrigin, VoterSecret};

// =========================================================================
// Wallet state
// =========================================================================

/// Connection + identity state of the browser wallet.
#[derive(Debug, Clone, Default)]
pub struct WalletState {
    /// The connected account address (hex string), or `None` if disconnected.
    pub address: Option<String>,
    /// The current chain id (hex string), or `None` if unknown.
    pub chain_id: Option<String>,
    /// Whether a connect request is in flight (for the spinner).
    pub connecting: bool,
    /// The last error from a wallet interaction.
    pub error: Option<String>,
}

// =========================================================================
// Vote submission lifecycle
// =========================================================================

/// Where a vote submission is in its lifecycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum VotePhase {
    /// Idle — no vote in progress.
    #[default]
    Idle,
    /// Building the Merkle witness + computing the nullifier.
    Witness,
    /// Generating the Groth16 proof (the long step, ~1-3s).
    Proving,
    /// POSTing to the relayer.
    Submitting,
    /// Done — relayer broadcast the tx.
    Done,
    /// Failed at some step.
    Failed,
}

/// The full state of a vote-in-progress.
#[derive(Debug, Clone, Default)]
pub struct VoteState {
    /// Current phase.
    pub phase: VotePhase,
    /// Human-readable status / error message.
    pub message: Option<String>,
    /// The broadcast transaction hash once available.
    pub tx_hash: Option<String>,
}

// =========================================================================
// Admin (create / close poll) lifecycle
// =========================================================================

/// Where an admin transaction (create/close poll) is in its lifecycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AdminTxPhase {
    /// Idle — no transaction in progress.
    #[default]
    Idle,
    /// Awaiting wallet signature + broadcast.
    Submitting,
    /// Wallet accepted and broadcast the transaction.
    Done,
    /// Failed at some step.
    Failed,
}

/// The state of an in-flight (or just-finished) admin transaction.
#[derive(Debug, Clone, Default)]
pub struct AdminTxState {
    /// Current phase.
    pub phase: AdminTxPhase,
    /// Human-readable status / error message.
    pub message: Option<String>,
    /// The broadcast transaction hash once available.
    pub tx_hash: Option<String>,
}

/// Move an admin-tx signal to a new phase, clearing any prior message.
pub fn set_admin_tx_phase(signal: RwSignal<AdminTxState>, phase: AdminTxPhase) {
    signal.update(|s| {
        s.phase = phase;
        s.message = None;
    });
}

/// Record an admin-tx failure.
pub fn admin_tx_failed(signal: RwSignal<AdminTxState>, msg: impl Into<String>) {
    signal.update(|s| {
        s.phase = AdminTxPhase::Failed;
        s.message = Some(msg.into());
    });
}

/// Record a successful admin-tx broadcast.
pub fn admin_tx_done(signal: RwSignal<AdminTxState>, tx_hash: String) {
    signal.update(|s| {
        s.phase = AdminTxPhase::Done;
        s.tx_hash = Some(tx_hash);
    });
}

// =========================================================================
// Voter registration lifecycle (the "Register to Vote" page)
// =========================================================================

/// Where a `POST /api/register` submission is in its lifecycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RegisterPhase {
    /// Idle — nothing submitted yet this session.
    #[default]
    Idle,
    /// Computing the commitment and POSTing to the relayer.
    Submitting,
    /// Relayer accepted the commitment.
    Done,
    /// Failed at some step.
    Failed,
}

/// The state of an in-flight (or just-finished) registration submission.
#[derive(Debug, Clone, Default)]
pub struct RegisterState {
    /// Current phase.
    pub phase: RegisterPhase,
    /// Human-readable status / error message.
    pub message: Option<String>,
    /// Total commitments pending (not yet locked into a poll) after a
    /// successful submission, as reported by the relayer.
    pub total_pending: Option<usize>,
}

// =========================================================================
// Admin whitelist-building lifecycle (snapshot -> build tree -> publish)
// =========================================================================

/// Where the admin's "build whitelist from registrations" flow is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum WhitelistBuildPhase {
    /// Idle — no build in progress.
    #[default]
    Idle,
    /// Snapshotting the pending batch and building the Merkle tree.
    Building,
    /// Tree built and published; `merkle_root` is ready to use.
    Done,
    /// Failed at some step.
    Failed,
}

/// The state of an in-flight (or just-finished) whitelist build.
#[derive(Debug, Clone, Default)]
pub struct WhitelistBuildState {
    /// Current phase.
    pub phase: WhitelistBuildPhase,
    /// Human-readable status / error message.
    pub message: Option<String>,
    /// The computed Merkle root (0x-prefixed hex), once built.
    pub merkle_root: Option<String>,
    /// How many commitments went into the tree.
    pub commitment_count: Option<usize>,
}

// =========================================================================
// Voter secret (derivation / backup / restore)
// =========================================================================

/// Everything the UI knows about the voter's secret for the connected
/// account.
///
/// The secret itself is a `String` (decimal, as the circuit consumes it)
/// rather than a `U256` so views never have to format it — and it is only
/// ever rendered behind an explicit "reveal" toggle, because anyone who reads
/// it off a screen can vote as this voter forever.
#[derive(Debug, Clone, Default)]
pub struct SecretState {
    /// The resolved secret in decimal, or `None` if it hasn't been derived
    /// or loaded yet this session.
    pub value: Option<String>,
    /// Where [`Self::value`] came from, which decides what the backup panel
    /// warns about.
    pub origin: Option<SecretOrigin>,
    /// A derivation / import / migration is in flight (usually waiting on a
    /// wallet signature prompt).
    pub busy: bool,
    /// A hard failure: the secret could not be resolved at all.
    pub error: Option<String>,
    /// A *soft* failure: the secret is usable now but could not be cached.
    ///
    /// This is the field that exists because the old code wrote
    /// `let _ = local_storage_set(...)`. It is never allowed to be `Some`
    /// without the UI rendering it.
    pub storage_warning: Option<String>,
    /// A transient success message ("Imported.", "Cleared.").
    pub notice: Option<String>,
    /// Whether the voter has asked to see the plaintext secret.
    pub revealed: bool,
}

// =========================================================================
// Registration review (approve / reject) lifecycle
// =========================================================================

/// Where an approve/reject submission is in its lifecycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ReviewPhase {
    /// Idle — nothing submitted yet.
    #[default]
    Idle,
    /// POSTing to the relayer.
    Submitting,
    /// The relayer applied the decision.
    Done,
    /// Failed at some step.
    Failed,
}

/// The state of an in-flight (or just-finished) approve/reject call.
///
/// Kept separate from [`WhitelistBuildState`] on purpose: review and build
/// are two deliberate steps, and collapsing their status into one banner
/// would blur exactly the distinction the approval gate exists to enforce.
#[derive(Debug, Clone, Default)]
pub struct ReviewState {
    /// Current phase.
    pub phase: ReviewPhase,
    /// Human-readable status / error message.
    pub message: Option<String>,
    /// How many pending entries the relayer actually changed.
    pub affected: Option<usize>,
    /// Commitments the relayer did not recognise — surfaced rather than
    /// swallowed, so a stale list is visible instead of half-applied.
    pub unknown: Vec<alloy_primitives::U256>,
}

// =========================================================================
// Page navigation
// =========================================================================

/// Which screen is currently shown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum View {
    /// Poll list.
    #[default]
    List,
    /// A single poll detail + vote form.
    Detail(String),
    /// Voter registration (submit an identity commitment ahead of the next poll).
    Register,
    /// Poll administration (create / close), owner-only.
    Admin,
}

// =========================================================================
// App-wide signal bag
// =========================================================================

/// The top-level reactive state, created once in [`crate::app::App`] and
/// threaded down to components via context.
#[derive(Clone)]
pub struct AppSignals {
    /// Wallet connection.
    pub wallet: RwSignal<WalletState>,
    /// The poll list (None = not yet loaded).
    pub polls: RwSignal<Option<Vec<PollData>>>,
    /// Polls-loading error (network/relayer down).
    pub polls_error: RwSignal<Option<String>>,
    /// Currently-viewed poll's tally (loaded on demand in detail view).
    pub current_tally: RwSignal<Option<TallyResponse>>,
    /// Vote submission state.
    pub vote: RwSignal<VoteState>,
    /// Which view is active.
    pub view: RwSignal<View>,
    /// The voter's secret for the connected account: derived from a wallet
    /// signature, cached in `localStorage`, and backed up / restored through
    /// [`crate::components::SecretBackupPanel`]. See [`crate::secret`] for
    /// the derivation scheme and its tradeoffs.
    pub secret: RwSignal<SecretState>,
    /// Whether the connected wallet is the on-chain `VotingManager` owner.
    pub is_admin: RwSignal<bool>,
    /// The relayer's `ADMIN_API_KEY`, held **in memory only** for this page
    /// load — never `localStorage`, never `sessionStorage`. See
    /// [`crate::admin_key`] for why.
    pub admin_api_key: RwSignal<Option<String>>,
    /// Set once at startup if an older build had persisted the admin key to
    /// web storage. The key is deleted either way; this exists to tell the
    /// admin to rotate it, since deletion does not undo the exposure.
    pub admin_key_was_persisted: RwSignal<bool>,
    /// State of an in-flight "create poll" transaction.
    pub admin_create: RwSignal<AdminTxState>,
    /// State of an in-flight "close poll" transaction.
    pub admin_close: RwSignal<AdminTxState>,
    /// State of an in-flight "register to vote" submission.
    pub register: RwSignal<RegisterState>,
    /// State of an in-flight admin "build whitelist from registrations" flow.
    pub whitelist_build: RwSignal<WhitelistBuildState>,
    /// Count of currently-pending (not yet snapshotted) registrations, for
    /// the admin panel. `None` = not yet fetched.
    pub pending_registrations: RwSignal<Option<usize>>,
    /// Error from the last pending-registrations fetch, if any.
    pub pending_registrations_error: RwSignal<Option<String>>,
    /// The actual pending commitments most recently fetched.
    ///
    /// Held, not just counted, so the admin can *see* what they are about to
    /// approve — and so the approve call can name that exact batch instead of
    /// sending `all: true`, which would also sweep in anything that arrived
    /// since the refresh.
    pub pending_commitments: RwSignal<Option<Vec<alloy_primitives::U256>>>,
    /// State of an in-flight approve/reject submission.
    pub review: RwSignal<ReviewState>,
}

impl AppSignals {
    /// Create a fresh set of signals.
    pub fn new() -> Self {
        Self {
            wallet: RwSignal::new(WalletState::default()),
            polls: RwSignal::new(None),
            polls_error: RwSignal::new(None),
            current_tally: RwSignal::new(None),
            vote: RwSignal::new(VoteState::default()),
            view: RwSignal::new(View::List),
            secret: RwSignal::new(SecretState::default()),
            is_admin: RwSignal::new(false),
            admin_api_key: RwSignal::new(None),
            admin_key_was_persisted: RwSignal::new(false),
            admin_create: RwSignal::new(AdminTxState::default()),
            admin_close: RwSignal::new(AdminTxState::default()),
            register: RwSignal::new(RegisterState::default()),
            whitelist_build: RwSignal::new(WhitelistBuildState::default()),
            pending_registrations: RwSignal::new(None),
            pending_registrations_error: RwSignal::new(None),
            pending_commitments: RwSignal::new(None),
            review: RwSignal::new(ReviewState::default()),
        }
    }

    /// Set the wallet to "connecting".
    pub fn wallet_connecting(&self) {
        self.wallet.update(|w| {
            w.connecting = true;
            w.error = None;
        });
    }

    /// Record a successful wallet connection.
    pub fn wallet_connected(&self, address: String, chain_id: String) {
        self.wallet.update(|w| {
            w.address = Some(address);
            w.chain_id = Some(chain_id);
            w.connecting = false;
            w.error = None;
        });
    }

    /// Record a wallet error.
    pub fn wallet_error(&self, msg: impl Into<String>) {
        self.wallet.update(|w| {
            w.connecting = false;
            w.error = Some(msg.into());
        });
    }

    /// Move the vote state to a new phase.
    pub fn vote_phase(&self, phase: VotePhase) {
        self.vote.update(|v| {
            v.phase = phase;
            v.message = None;
        });
    }

    /// Record a vote submission error.
    pub fn vote_failed(&self, msg: impl Into<String>) {
        self.vote.update(|v| {
            v.phase = VotePhase::Failed;
            v.message = Some(msg.into());
        });
    }

    /// Record a successful broadcast.
    pub fn vote_done(&self, resp: VoteResponse) {
        self.vote.update(|v| {
            v.phase = VotePhase::Done;
            v.tx_hash = Some(resp.tx_hash);
        });
    }

    /// Reset vote state to idle.
    pub fn vote_reset(&self) {
        self.vote.set(VoteState::default());
    }

    /// Move the registration state to a new phase.
    pub fn register_phase(&self, phase: RegisterPhase) {
        self.register.update(|r| {
            r.phase = phase;
            r.message = None;
        });
    }

    /// Record a registration failure.
    pub fn register_failed(&self, msg: impl Into<String>) {
        self.register.update(|r| {
            r.phase = RegisterPhase::Failed;
            r.message = Some(msg.into());
        });
    }

    /// Record a successful registration.
    pub fn register_done(&self, total_pending: usize) {
        self.register.update(|r| {
            r.phase = RegisterPhase::Done;
            r.total_pending = Some(total_pending);
        });
    }

    /// Move the whitelist-build state to a new phase.
    pub fn whitelist_build_phase(&self, phase: WhitelistBuildPhase) {
        self.whitelist_build.update(|w| {
            w.phase = phase;
            w.message = None;
        });
    }

    /// Record a whitelist-build failure.
    pub fn whitelist_build_failed(&self, msg: impl Into<String>) {
        self.whitelist_build.update(|w| {
            w.phase = WhitelistBuildPhase::Failed;
            w.message = Some(msg.into());
        });
    }

    /// Record a successful whitelist build.
    pub fn whitelist_build_done(&self, merkle_root: String, commitment_count: usize) {
        self.whitelist_build.update(|w| {
            w.phase = WhitelistBuildPhase::Done;
            w.merkle_root = Some(merkle_root);
            w.commitment_count = Some(commitment_count);
        });
    }

    // ---- registration review --------------------------------------------

    /// Move the review state to a new phase, clearing the previous result so
    /// a stale "3 approved" can't sit next to a fresh attempt.
    pub fn review_phase(&self, phase: ReviewPhase) {
        self.review.update(|r| {
            r.phase = phase;
            r.message = None;
            r.affected = None;
            r.unknown.clear();
        });
    }

    /// Record a review failure.
    pub fn review_failed(&self, msg: impl Into<String>) {
        self.review.update(|r| {
            r.phase = ReviewPhase::Failed;
            r.message = Some(msg.into());
        });
    }

    /// Record a completed approve/reject, including the counts the relayer
    /// reported back.
    pub fn review_done(
        &self,
        msg: impl Into<String>,
        affected: usize,
        unknown: Vec<alloy_primitives::U256>,
    ) {
        self.review.update(|r| {
            r.phase = ReviewPhase::Done;
            r.message = Some(msg.into());
            r.affected = Some(affected);
            r.unknown = unknown;
        });
    }

    // ---- voter secret ----------------------------------------------------

    /// Mark a secret derivation / import / migration as in flight, clearing
    /// stale messages so the voter doesn't read last attempt's error as this
    /// attempt's result.
    pub fn secret_busy(&self) {
        self.secret.update(|s| {
            s.busy = true;
            s.error = None;
            s.notice = None;
        });
    }

    /// Record a resolved secret.
    ///
    /// A [`VoterSecret::storage_warning`] is copied straight into
    /// [`SecretState::storage_warning`] so it cannot be dropped on the floor:
    /// this is the one function that turns "the cache write failed" into
    /// something the voter can actually see.
    pub fn secret_resolved(&self, resolved: &VoterSecret) {
        self.secret.update(|s| {
            s.busy = false;
            s.error = None;
            s.value = Some(resolved.value.to_string());
            s.origin = Some(resolved.origin);
            s.storage_warning = resolved
                .storage_warning
                .as_ref()
                .map(|e| e.user_message());
        });
    }

    /// Record a hard secret failure. Leaves any previously-resolved value in
    /// place: a failed *re-derivation* shouldn't blank out a secret the voter
    /// can still export.
    pub fn secret_failed(&self, msg: impl Into<String>) {
        self.secret.update(|s| {
            s.busy = false;
            s.error = Some(msg.into());
        });
    }

    /// Record a transient success message on the secret panel.
    pub fn secret_notice(&self, msg: impl Into<String>) {
        self.secret.update(|s| {
            s.busy = false;
            s.error = None;
            s.notice = Some(msg.into());
        });
    }

    /// Drop the in-memory copy of the secret (after an explicit "forget", or
    /// when the account changes). Does not touch storage.
    pub fn secret_cleared(&self) {
        self.secret.update(|s| {
            s.value = None;
            s.origin = None;
            s.revealed = false;
            s.busy = false;
            s.storage_warning = None;
        });
    }

    // ---- relayer admin API key -------------------------------------------

    /// Store the admin API key for this page load. Blank input clears it.
    ///
    /// In-memory only — see [`crate::admin_key`]. Nothing in this path writes
    /// to `localStorage` or `sessionStorage`.
    pub fn set_admin_api_key(&self, key: impl Into<String>) {
        let key = key.into();
        self.admin_api_key.set(crate::admin_key::is_usable(&key).then_some(key));
    }

    /// Forget the admin API key immediately.
    ///
    /// Called from the admin panel's explicit "Clear key" control and
    /// automatically whenever the wallet disconnects or switches accounts —
    /// a new account is a new person as far as this app can tell.
    pub fn clear_admin_api_key(&self) {
        self.admin_api_key.set(None);
    }

    /// The current admin key, or an empty string when none is loaded.
    ///
    /// Untracked on purpose: this is read inside event handlers that submit a
    /// request, and making them reactive on the key would re-run them on
    /// every keystroke.
    pub fn admin_api_key_value(&self) -> String {
        self.admin_api_key.get_untracked().unwrap_or_default()
    }
}

impl Default for AppSignals {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leptos::SignalGetUntracked;

    #[test]
    fn default_view_is_list() {
        assert_eq!(View::default(), View::List);
    }

    #[test]
    fn new_signals_start_idle_and_disconnected() {
        let signals = AppSignals::new();
        assert!(signals.wallet.get_untracked().address.is_none());
        assert!(!signals.wallet.get_untracked().connecting);
        assert_eq!(signals.vote.get_untracked().phase, VotePhase::Idle);
        assert_eq!(signals.view.get_untracked(), View::List);
        assert!(signals.polls.get_untracked().is_none());
        assert!(!signals.is_admin.get_untracked());
        assert_eq!(signals.admin_create.get_untracked().phase, AdminTxPhase::Idle);
        assert_eq!(signals.admin_close.get_untracked().phase, AdminTxPhase::Idle);
    }

    #[test]
    fn default_impl_matches_new() {
        let signals = AppSignals::default();
        assert!(signals.wallet.get_untracked().address.is_none());
        assert_eq!(signals.view.get_untracked(), View::List);
    }

    #[test]
    fn wallet_connecting_clears_prior_error() {
        let signals = AppSignals::new();
        signals.wallet_error("boom");
        assert_eq!(signals.wallet.get_untracked().error.as_deref(), Some("boom"));

        signals.wallet_connecting();
        let w = signals.wallet.get_untracked();
        assert!(w.connecting);
        assert!(w.error.is_none());
    }

    #[test]
    fn wallet_connected_sets_address_chain_and_clears_flags() {
        let signals = AppSignals::new();
        signals.wallet_connecting();
        signals.wallet_connected("0xabc".into(), "0x1".into());

        let w = signals.wallet.get_untracked();
        assert_eq!(w.address.as_deref(), Some("0xabc"));
        assert_eq!(w.chain_id.as_deref(), Some("0x1"));
        assert!(!w.connecting);
        assert!(w.error.is_none());
    }

    #[test]
    fn wallet_error_stops_connecting_and_preserves_address() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xabc".into(), "0x1".into());
        signals.wallet_connecting();
        signals.wallet_error("wallet rejected connection");

        let w = signals.wallet.get_untracked();
        assert!(!w.connecting);
        assert_eq!(w.error.as_deref(), Some("wallet rejected connection"));
        // Disconnecting is a separate, explicit action; an error mid-reconnect
        // should not silently drop the previously-known address.
        assert_eq!(w.address.as_deref(), Some("0xabc"));
    }

    #[test]
    fn vote_phase_transitions_clear_message() {
        let signals = AppSignals::new();
        signals.vote_failed("nope");
        assert!(signals.vote.get_untracked().message.is_some());

        signals.vote_phase(VotePhase::Witness);
        let v = signals.vote.get_untracked();
        assert_eq!(v.phase, VotePhase::Witness);
        assert!(v.message.is_none());
    }

    #[test]
    fn vote_failed_sets_phase_and_message() {
        let signals = AppSignals::new();
        signals.vote_failed("proof generation failed");
        let v = signals.vote.get_untracked();
        assert_eq!(v.phase, VotePhase::Failed);
        assert_eq!(v.message.as_deref(), Some("proof generation failed"));
    }

    #[test]
    fn vote_done_sets_phase_and_tx_hash() {
        let signals = AppSignals::new();
        signals.vote_done(VoteResponse {
            tx_hash: "0xdead".into(),
            status: viche_core::wire::VoteStatus::Broadcast,
        });
        let v = signals.vote.get_untracked();
        assert_eq!(v.phase, VotePhase::Done);
        assert_eq!(v.tx_hash.as_deref(), Some("0xdead"));
    }

    #[test]
    fn vote_reset_returns_to_default_state() {
        let signals = AppSignals::new();
        signals.vote_failed("nope");
        signals.vote_reset();
        let v = signals.vote.get_untracked();
        assert_eq!(v.phase, VotePhase::Idle);
        assert!(v.message.is_none());
        assert!(v.tx_hash.is_none());
    }

    #[test]
    fn set_admin_tx_phase_clears_message_but_keeps_tx_hash() {
        let signal = RwSignal::new(AdminTxState::default());
        admin_tx_failed(signal, "bad input");
        assert!(signal.get_untracked().message.is_some());

        set_admin_tx_phase(signal, AdminTxPhase::Submitting);
        let s = signal.get_untracked();
        assert_eq!(s.phase, AdminTxPhase::Submitting);
        assert!(s.message.is_none());
    }

    #[test]
    fn admin_tx_failed_sets_phase_and_message() {
        let signal = RwSignal::new(AdminTxState::default());
        admin_tx_failed(signal, "Invalid merkle root: expected 32 bytes, got 10");
        let s = signal.get_untracked();
        assert_eq!(s.phase, AdminTxPhase::Failed);
        assert_eq!(
            s.message.as_deref(),
            Some("Invalid merkle root: expected 32 bytes, got 10")
        );
    }

    #[test]
    fn admin_tx_done_sets_phase_and_tx_hash() {
        let signal = RwSignal::new(AdminTxState::default());
        admin_tx_done(signal, "0xfeed".into());
        let s = signal.get_untracked();
        assert_eq!(s.phase, AdminTxPhase::Done);
        assert_eq!(s.tx_hash.as_deref(), Some("0xfeed"));
    }

    #[test]
    fn register_phase_transitions_clear_message() {
        let signals = AppSignals::new();
        signals.register_failed("nope");
        assert!(signals.register.get_untracked().message.is_some());

        signals.register_phase(RegisterPhase::Submitting);
        let r = signals.register.get_untracked();
        assert_eq!(r.phase, RegisterPhase::Submitting);
        assert!(r.message.is_none());
    }

    #[test]
    fn register_done_sets_phase_and_pending_count() {
        let signals = AppSignals::new();
        signals.register_done(3);
        let r = signals.register.get_untracked();
        assert_eq!(r.phase, RegisterPhase::Done);
        assert_eq!(r.total_pending, Some(3));
    }

    #[test]
    fn whitelist_build_done_sets_phase_root_and_count() {
        let signals = AppSignals::new();
        signals.whitelist_build_done("0xabc".into(), 5);
        let w = signals.whitelist_build.get_untracked();
        assert_eq!(w.phase, WhitelistBuildPhase::Done);
        assert_eq!(w.merkle_root.as_deref(), Some("0xabc"));
        assert_eq!(w.commitment_count, Some(5));
    }

    #[test]
    fn whitelist_build_failed_sets_phase_and_message() {
        let signals = AppSignals::new();
        signals.whitelist_build_failed("no registrations to snapshot");
        let w = signals.whitelist_build.get_untracked();
        assert_eq!(w.phase, WhitelistBuildPhase::Failed);
        assert_eq!(w.message.as_deref(), Some("no registrations to snapshot"));
    }

    // ---- voter secret ----------------------------------------------------

    fn voter_secret(value: u64, origin: SecretOrigin) -> VoterSecret {
        VoterSecret {
            value: alloy_primitives::U256::from(value),
            origin,
            storage_warning: None,
        }
    }

    #[test]
    fn secret_starts_empty_and_hidden() {
        let s = AppSignals::new().secret.get_untracked();
        assert!(s.value.is_none());
        assert!(s.origin.is_none());
        assert!(!s.revealed);
        assert!(!s.busy);
    }

    #[test]
    fn secret_resolved_publishes_value_and_origin() {
        let signals = AppSignals::new();
        signals.secret_busy();
        assert!(signals.secret.get_untracked().busy);

        signals.secret_resolved(&voter_secret(99, SecretOrigin::WalletDerivedV1));
        let s = signals.secret.get_untracked();
        assert!(!s.busy);
        assert_eq!(s.value.as_deref(), Some("99"));
        assert_eq!(s.origin, Some(SecretOrigin::WalletDerivedV1));
        assert!(s.storage_warning.is_none());
    }

    #[test]
    fn secret_resolved_surfaces_a_storage_failure_instead_of_dropping_it() {
        // The regression guard for the original `let _ = local_storage_set(..)`:
        // a failed cache write must reach a field the UI renders.
        let signals = AppSignals::new();
        signals.secret_resolved(&VoterSecret {
            value: alloy_primitives::U256::from(1u64),
            origin: SecretOrigin::WalletDerivedV1,
            storage_warning: Some(crate::storage::StorageError::QuotaExceeded {
                area: "localStorage",
            }),
        });
        let warning = signals
            .secret
            .get_untracked()
            .storage_warning
            .expect("storage failure was swallowed");
        assert!(warning.contains("localStorage"), "unhelpful warning: {warning}");
    }

    #[test]
    fn secret_failed_keeps_a_previously_resolved_value_exportable() {
        let signals = AppSignals::new();
        signals.secret_resolved(&voter_secret(5, SecretOrigin::LegacyRandom));
        signals.secret_failed("wallet refused");

        let s = signals.secret.get_untracked();
        assert_eq!(s.error.as_deref(), Some("wallet refused"));
        // Still exportable: a failed re-derivation must not blank out a
        // secret the voter could otherwise still back up.
        assert_eq!(s.value.as_deref(), Some("5"));
    }

    #[test]
    fn secret_notice_clears_a_stale_error() {
        let signals = AppSignals::new();
        signals.secret_failed("boom");
        signals.secret_notice("imported");
        let s = signals.secret.get_untracked();
        assert!(s.error.is_none());
        assert_eq!(s.notice.as_deref(), Some("imported"));
    }

    #[test]
    fn secret_cleared_drops_the_value_and_re_hides_the_panel() {
        let signals = AppSignals::new();
        signals.secret_resolved(&voter_secret(5, SecretOrigin::Imported));
        signals.secret.update(|s| s.revealed = true);

        signals.secret_cleared();
        let s = signals.secret.get_untracked();
        assert!(s.value.is_none());
        assert!(s.origin.is_none());
        assert!(!s.revealed);
    }

    // ---- registration review ---------------------------------------------

    #[test]
    fn review_starts_idle_with_no_pending_list() {
        let signals = AppSignals::new();
        assert_eq!(signals.review.get_untracked().phase, ReviewPhase::Idle);
        assert!(signals.pending_commitments.get_untracked().is_none());
    }

    #[test]
    fn review_done_records_affected_and_unknown() {
        let signals = AppSignals::new();
        signals.review_done("Approved 2 of 3.", 2, vec![alloy_primitives::U256::from(9u64)]);
        let r = signals.review.get_untracked();
        assert_eq!(r.phase, ReviewPhase::Done);
        assert_eq!(r.affected, Some(2));
        assert_eq!(r.unknown.len(), 1);
        assert_eq!(r.message.as_deref(), Some("Approved 2 of 3."));
    }

    #[test]
    fn review_phase_clears_a_stale_result() {
        let signals = AppSignals::new();
        signals.review_done("done", 5, vec![alloy_primitives::U256::from(1u64)]);
        signals.review_phase(ReviewPhase::Submitting);

        let r = signals.review.get_untracked();
        assert_eq!(r.phase, ReviewPhase::Submitting);
        assert!(r.affected.is_none());
        assert!(r.unknown.is_empty());
        assert!(r.message.is_none());
    }

    #[test]
    fn review_failed_sets_phase_and_message() {
        let signals = AppSignals::new();
        signals.review_failed("relayer said no");
        let r = signals.review.get_untracked();
        assert_eq!(r.phase, ReviewPhase::Failed);
        assert_eq!(r.message.as_deref(), Some("relayer said no"));
    }

    // ---- relayer admin API key -------------------------------------------

    #[test]
    fn admin_api_key_starts_unset() {
        let signals = AppSignals::new();
        assert!(signals.admin_api_key.get_untracked().is_none());
        assert_eq!(signals.admin_api_key_value(), "");
        assert!(!signals.admin_key_was_persisted.get_untracked());
    }

    #[test]
    fn set_admin_api_key_treats_blank_input_as_clearing() {
        let signals = AppSignals::new();
        signals.set_admin_api_key("k3y");
        assert_eq!(signals.admin_api_key_value(), "k3y");

        signals.set_admin_api_key("");
        assert!(signals.admin_api_key.get_untracked().is_none());
    }

    #[test]
    fn clear_admin_api_key_is_idempotent() {
        let signals = AppSignals::new();
        signals.clear_admin_api_key();
        signals.clear_admin_api_key();
        assert!(signals.admin_api_key.get_untracked().is_none());
    }

    #[test]
    fn admin_create_and_admin_close_signals_are_independent() {
        let signals = AppSignals::new();
        admin_tx_failed(signals.admin_create, "create failed");
        admin_tx_done(signals.admin_close, "0x123".into());

        assert_eq!(signals.admin_create.get_untracked().phase, AdminTxPhase::Failed);
        assert_eq!(signals.admin_close.get_untracked().phase, AdminTxPhase::Done);
    }
}
