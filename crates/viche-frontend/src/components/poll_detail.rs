//! Poll detail view — metadata, tallies, and the vote form.

use leptos::SignalGet;
use leptos::*;
use web_sys::MouseEvent;

use crate::state::{AppSignals, View, VotePhase};

/// The poll detail screen.
#[component]
pub fn PollDetail(#[prop(into)] signals: AppSignals, poll_id: String) -> impl IntoView {
    let polls = signals.polls;
    let tally = signals.current_tally;
    let vote = signals.vote;
    let view = signals.view;

    // Look up the poll metadata from the cached list.
    let poll = move || {
        polls
            .get()
            .and_then(|list| list.into_iter().find(|p| p.poll_id.to_string() == poll_id))
    };

    // Local signal for the selected option index.
    let selected = create_rw_signal(None::<usize>);

    view! {
        <section class="max-w-3xl mx-auto px-4 py-8">
            <button
                class="text-sm text-slate-400 hover:text-slate-200 mb-4"
                on:click=move |_| { view.set(View::List); }
            >
                "<- Back to polls"
            </button>

            {move || {
                let Some(p) = poll() else {
                    return view! {
                        <div class="text-slate-500">"Poll not found."</div>
                    }.into_view();
                };

                view! {
                    <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-6">
                        <div class="flex items-center justify-between mb-4">
                            <h2 class="text-2xl font-semibold">"Poll #" {p.poll_id.to_string()}</h2>
                            <span class="text-xs text-slate-500">
                                {p.num_options.to_string()} " options"
                            </span>
                        </div>
                        <p class="text-sm text-slate-400 font-mono break-all" title="Merkle root">
                            "root: " {p.merkle_root.to_string()}
                        </p>
                        <p class="text-sm text-slate-400 mt-1">
                            "total votes: " {p.total_votes.to_string()}
                        </p>
                    </div>

                    <TallyBars tally=tally.read_only() />

                    <VoteForm
                        signals=signals.clone()
                        poll_id=p.poll_id.to_string()
                        merkle_root=p.merkle_root.to_string()
                        num_options=p.num_options
                        selected=selected
                    />
                }.into_view()
            }}
        </section>
    }
}

/// Horizontal bar chart of the current tallies.
#[component]
fn TallyBars(tally: leptos::ReadSignal<Option<viche_core::wire::TallyResponse>>) -> impl IntoView {
    view! {
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-6">
            <h3 class="text-sm font-medium text-slate-300 mb-4">"Current Tally"</h3>
            {move || {
                let Some(t) = tally.get() else {
                    return view! {
                        <div class="text-slate-500 text-sm">"Loading tally..."</div>
                    }.into_view();
                };
                let total: u128 = t.option_tallies.iter()
                    .map(|v| u256_to_u128(*v))
                    .sum();
                if total == 0 {
                    return view! {
                        <div class="text-slate-500 text-sm">"No votes cast yet."</div>
                    }.into_view();
                }
                t.option_tallies.iter().enumerate().map(|(i, v)| {
                    let count = u256_to_u128(*v);
                    let pct = if total > 0 { (count as f64 / total as f64) * 100.0 } else { 0.0 };
                    view! {
                        <div class="mb-3">
                            <div class="flex justify-between text-xs text-slate-400 mb-1">
                                <span>"Option " {i}</span>
                                <span>{count.to_string()} " (" {format!("{:.0}", pct)} "%)"</span>
                            </div>
                            <div class="h-2 bg-slate-800 rounded-full overflow-hidden">
                                <div class="h-full bg-brand-500 rounded-full" style=format!("width: {}%", pct)></div>
                            </div>
                        </div>
                    }
                }).collect::<Vec<_>>().into_view()
            }}
        </div>
    }
}

/// The vote form: pick an option, then run the proving pipeline.
#[component]
fn VoteForm(
    #[prop(into)] signals: AppSignals,
    poll_id: String,
    merkle_root: String,
    num_options: alloy_primitives::U256,
    selected: leptos::RwSignal<Option<usize>>,
) -> impl IntoView {
    let vote = signals.vote;
    let num: usize = u256_to_u128(num_options) as usize;
    let pid = poll_id.clone();
    let mroot = merkle_root.clone();

    let on_vote = move |_: MouseEvent| {
        let opt = match selected.get() {
            Some(o) => o,
            None => {
                signals.vote_failed("Select an option first.");
                return;
            }
        };
        crate::actions::cast_vote(signals.clone(), pid.clone(), mroot.clone(), opt);
    };

    let is_busy = move || {
        matches!(
            vote.get().phase,
            VotePhase::Witness | VotePhase::Proving | VotePhase::Submitting
        )
    };

    view! {
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6">
            <h3 class="text-sm font-medium text-slate-300 mb-4">"Cast Your Vote"</h3>

            <div class="space-y-2 mb-6">
                {(0..num).map(|i| {
                    let button_class = move || {
                        if selected.get() == Some(i) {
                            "w-full text-left px-4 py-3 rounded-lg border transition border-brand-600 bg-brand-900/30"
                        } else {
                            "w-full text-left px-4 py-3 rounded-lg border transition border-slate-700 bg-slate-800/50"
                        }
                    };
                    let radio_class = move || {
                        if selected.get() == Some(i) {
                            "w-4 h-4 rounded-full border-2 flex items-center justify-center border-brand-500"
                        } else {
                            "w-4 h-4 rounded-full border-2 flex items-center justify-center border-slate-600"
                        }
                    };
                    let is_sel = move || selected.get() == Some(i);
                    view! {
                        <button
                            class=button_class
                            on:click=move |_| selected.set(Some(i))
                        >
                            <div class="flex items-center gap-3">
                                <span class=radio_class>
                                    {move || if is_sel() {
                                        view! { <span class="w-2 h-2 rounded-full bg-brand-400"></span> }.into_view()
                                    } else {
                                        view! { <span></span> }.into_view()
                                    }}
                                </span>
                                <span>"Option " {i}</span>
                            </div>
                        </button>
                    }
                }).collect::<Vec<_>>()}
            </div>

            <button
                class="w-full py-3 rounded-lg bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium transition"
                on:click=on_vote
                disabled=is_busy()
            >
                {move || match vote.get().phase {
                    VotePhase::Idle => "Cast Vote",
                    VotePhase::Witness => "Building witness...",
                    VotePhase::Proving => "Generating proof... (this can take a few seconds)",
                    VotePhase::Submitting => "Submitting to relayer...",
                    VotePhase::Done => "Vote submitted!",
                    VotePhase::Failed => "Retry",
                }}
            </button>

            {move || {
                let v = vote.get();
                match v.phase {
                    VotePhase::Done => {
                        let hash = v.tx_hash.unwrap_or_default();
                        view! {
                            <div class="mt-4 p-3 rounded-lg bg-emerald-900/30 border border-emerald-800 text-emerald-200 text-sm">
                                "Vote broadcast! Tx: "
                                <span class="font-mono break-all">{hash}</span>
                            </div>
                        }.into_view()
                    }
                    VotePhase::Failed => {
                        let msg = v.message.unwrap_or_else(|| "Unknown error".into());
                        view! {
                            <div class="mt-4 p-3 rounded-lg bg-red-900/30 border border-red-800 text-red-200 text-sm">
                                {msg}
                            </div>
                        }.into_view()
                    }
                    _ => view! { <span></span> }.into_view(),
                }
            }}
        </div>
    }
}

/// Convert a U256 to u128 (saturating — tallies and option counts are small).
fn u256_to_u128(v: alloy_primitives::U256) -> u128 {
    let bytes = v.to_le_bytes::<32>();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    u128::from_le_bytes(buf)
}
