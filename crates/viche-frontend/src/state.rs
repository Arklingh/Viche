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
// Page navigation
// =========================================================================

/// Which screen is currently shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum View {
    /// Poll list.
    List,
    /// A single poll detail + vote form.
    Detail(String),
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
