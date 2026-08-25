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
// Page navigation
// =========================================================================

/// Which screen is currently shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum View {
    /// Poll list.
    List,
    /// A single poll detail + vote form.
    Detail(String),
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
    fn admin_create_and_admin_close_signals_are_independent() {
        let signals = AppSignals::new();
        admin_tx_failed(signals.admin_create, "create failed");
        admin_tx_done(signals.admin_close, "0x123".into());

        assert_eq!(signals.admin_create.get_untracked().phase, AdminTxPhase::Failed);
        assert_eq!(signals.admin_close.get_untracked().phase, AdminTxPhase::Done);
    }
}
