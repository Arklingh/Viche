//! Global reactive state for the Viche SPA.
//!
//! Built on Leptos signals. The signals here are the single source of truth
//! for UI state; components read them reactively and write through typed
//! actions, keeping the view macros free of business logic.

use leptos::{RwSignal, SignalGet, SignalSet, SignalUpdate};
use viche_core::wire::{PollData, TallyResponse, VoteResponse};

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
// Page navigation
// =========================================================================

/// Which screen is currently shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum View {
    /// Poll list.
    List,
    /// A single poll detail + vote form.
    Detail(String),
    /// Voter registration (submit an identity commitment ahead of the next poll).
    Register,
    /// Poll administration (create / close), owner-only.
    Admin,
}

impl Default for View {
    fn default() -> Self {
        View::List
    }
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
    /// The voter's secret, keyed to the connected account in localStorage.
    pub secret: RwSignal<Option<String>>,
    /// Whether the connected wallet is the on-chain `VotingManager` owner.
    pub is_admin: RwSignal<bool>,
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
            secret: RwSignal::new(None),
            is_admin: RwSignal::new(false),
            admin_create: RwSignal::new(AdminTxState::default()),
            admin_close: RwSignal::new(AdminTxState::default()),
            register: RwSignal::new(RegisterState::default()),
            whitelist_build: RwSignal::new(WhitelistBuildState::default()),
            pending_registrations: RwSignal::new(None),
            pending_registrations_error: RwSignal::new(None),
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

    #[test]
    fn admin_create_and_admin_close_signals_are_independent() {
        let signals = AppSignals::new();
        admin_tx_failed(signals.admin_create, "create failed");
        admin_tx_done(signals.admin_close, "0x123".into());

        assert_eq!(signals.admin_create.get_untracked().phase, AdminTxPhase::Failed);
        assert_eq!(signals.admin_close.get_untracked().phase, AdminTxPhase::Done);
    }
}
