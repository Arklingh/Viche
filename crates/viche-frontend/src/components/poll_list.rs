//! Poll list view — the landing screen.

use leptos::*;
use viche_core::wire::PollData;

use crate::state::{AppSignals, View};

/// The poll list screen.
#[component]
pub fn PollList(#[prop(into)] signals: AppSignals) -> impl IntoView {
    let polls = signals.polls;
    let polls_error = signals.polls_error;

    // Clone for the refresh button closure.
    let refresh_signals = signals.clone();

    // Trigger a fetch on mount if we don't have data yet.
    crate::actions::fetch_polls_on_mount(signals.clone());

    view! {
        <section class="max-w-5xl mx-auto px-4 py-8">
            <div class="flex items-center justify-between mb-6">
                <h2 class="text-2xl font-semibold">"Active Votes"</h2>
                <button
                    class="text-sm px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800"
                    on:click=move |_| { crate::actions::refresh_polls(refresh_signals.clone()); }
                >
                    "Refresh"
                </button>
            </div>

            {move || {
                if let Some(e) = polls_error.get() {
                    view! {
                        <div class="bg-red-900/40 border border-red-800 text-red-200 rounded-lg p-4">
                            <p class="font-medium">"Failed to load polls"</p>
                            <p class="text-sm mt-1">{e}</p>
                        </div>
                    }.into_view()
                } else if let Some(list) = polls.get() {
                    if list.is_empty() {
                        view! {
                            <div class="text-slate-500 text-center py-16">
                                "No polls have been created yet."
                            </div>
                        }.into_view()
                    } else {
                        list.iter()
                            .map(|p| {
                                let card_signals = signals.clone();
                                view! { <PollCard signals=card_signals poll=p.clone() /> }
                            })
                            .collect::<Vec<_>>()
                            .into_view()
                    }
                } else {
                    view! {
                        <div class="viche-shimmer h-24 rounded-lg"></div>
                        <div class="viche-shimmer h-24 rounded-lg mt-3"></div>
                    }.into_view()
                }
            }}
        </section>
    }
}

/// A single poll card in the list.
#[component]
fn PollCard(#[prop(into)] signals: AppSignals, poll: PollData) -> impl IntoView {
    let view_signal = signals.view;
    let poll_id = poll.poll_id.to_string();
    let poll_id_for_click = poll_id.clone();
    let poll_id_for_tally = poll_id.clone();

    view! {
        <button
            class="w-full text-left bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-brand-600 hover:bg-slate-800/50 transition mb-3"
            on:click=move |_| {
                view_signal.set(View::Detail(poll_id_for_click.clone()));
                crate::actions::fetch_tally(signals.clone(), poll_id_for_tally.clone());
            }
        >
            <div class="flex items-start justify-between gap-4">
                <div>
                    <div class="flex items-center gap-2 mb-1">
                        <PollStatusBadge active=poll.active />
                        <span class="text-xs text-slate-500">"Poll #"{poll_id.clone()}</span>
                    </div>
                    <p class="text-slate-300">
                        {poll.num_options.to_string()}
                        " options"
                    </p>
                </div>
                <div class="text-right">
                    <p class="text-2xl font-semibold text-brand-400">
                        {poll.total_votes.to_string()}
                    </p>
                    <p class="text-xs text-slate-500">"votes"</p>
                </div>
            </div>
            <p class="text-xs text-slate-500 mt-3 font-mono truncate" title=poll.merkle_root.to_string()>
                "root " {shorten_hex(&poll.merkle_root.to_string())}
            </p>
        </button>
    }
}

/// Coloured status pill.
#[component]
fn PollStatusBadge(active: bool) -> impl IntoView {
    let (label, classes) = if !active {
        ("Closed", "bg-slate-700 text-slate-300")
    } else {
        (
            "Active",
            "bg-emerald-900/50 text-emerald-300 border border-emerald-800",
        )
    };
    view! {
        <span class=format!("text-xs px-2 py-0.5 rounded-full {}", classes)>
            {label}
        </span>
    }
}

fn shorten_hex(s: &str) -> String {
    let len = s.len();
    if len <= 12 {
        return s.to_string();
    }
    format!("{}...{}", &s[..8], &s[len - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorten_hex_leaves_short_strings_untouched() {
        assert_eq!(shorten_hex("0xabcd"), "0xabcd");
        assert_eq!(shorten_hex("0x1234abcd"), "0x1234abcd"); // exactly 12 chars
    }

    #[test]
    fn shorten_hex_truncates_long_roots() {
        let root = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";
        assert_eq!(shorten_hex(root), "0x123456...90ab");
    }
}
