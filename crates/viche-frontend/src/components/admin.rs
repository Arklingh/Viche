//! Admin page — create and close polls.
//!
//! Gated on the connected wallet matching the on-chain `VotingManager.owner`
//! (checked in [`crate::actions::check_admin`]). Both actions sign and
//! broadcast a transaction directly from the wallet — see [`crate::onchain`]
//! for why this bypasses the relayer.

use leptos::*;
use web_sys::{MouseEvent, SubmitEvent};

use crate::state::{AdminTxPhase, AppSignals, WhitelistBuildPhase};

/// The admin page: gate, then voter registration, the create-poll form, and
/// the poll-management list.
#[component]
pub fn AdminPage(#[prop(into)] signals: AppSignals) -> impl IntoView {
    let wallet = signals.wallet;
    let is_admin = signals.is_admin;

    crate::actions::fetch_polls_on_mount(signals.clone());

    // Shared between the registration panel (which computes it) and the
    // create-poll form (which submits it) — lifted here so a successful
    // whitelist build can auto-fill the form.
    let merkle_root = create_rw_signal(String::new());
    {
        let wb = signals.whitelist_build;
        create_effect(move |_| {
            let w = wb.get();
            if w.phase == WhitelistBuildPhase::Done {
                if let Some(root) = w.merkle_root {
                    merkle_root.set(root);
                }
            }
        });
    }

    let registration_signals = signals.clone();
    let create_signals = signals.clone();
    let manage_signals = signals.clone();

    view! {
        <section class="max-w-3xl mx-auto px-4 py-8">
            <h2 class="text-2xl font-semibold mb-6">"Poll Admin"</h2>

            {move || {
                let w = wallet.get();
                if w.address.is_none() {
                    view! {
                        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 text-slate-400 text-sm">
                            "Connect the poll-admin wallet to create or close polls."
                        </div>
                    }.into_view()
                } else if !is_admin.get() {
                    view! {
                        <div class="bg-amber-900/30 border border-amber-800 text-amber-200 rounded-xl p-6 text-sm">
                            "This wallet is not the poll administrator. Connect the "
                            "VotingManager owner wallet to manage polls."
                        </div>
                    }.into_view()
                } else {
                    view! {
                        <div>
                            <VoterRegistrationPanel signals=registration_signals.clone() merkle_root=merkle_root />
                            <CreatePollForm signals=create_signals.clone() merkle_root=merkle_root />
                            <ManagePolls signals=manage_signals.clone() />
                        </div>
                    }.into_view()
                }
            }}
        </section>
    }
}

/// Panel to close registration, build a Merkle tree from the collected
/// commitments, and publish the resulting root — see
/// [`crate::components::register::RegisterPage`] for the voter side.
///
/// Talks to the relayer's `/api/admin/registrations/*` routes, which use a
/// *separate* credential (`ADMIN_API_KEY`) from the wallet-based gate on
/// this page — see [`crate::actions::load_admin_api_key`].
#[component]
fn VoterRegistrationPanel(
    #[prop(into)] signals: AppSignals,
    merkle_root: RwSignal<String>,
) -> impl IntoView {
    let pending = signals.pending_registrations;
    let pending_error = signals.pending_registrations_error;
    let build = signals.whitelist_build;

    let api_key = create_rw_signal(crate::actions::load_admin_api_key().unwrap_or_default());

    let is_building = move || build.get().phase == WhitelistBuildPhase::Building;

    view! {
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-6">
            <h3 class="text-sm font-medium text-slate-300 mb-4">"Voter Registration"</h3>

            <label class="block text-xs text-slate-400 mb-1">"Relayer admin API key"</label>
            <input
                class="w-full mb-3 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm font-mono"
                type="password"
                placeholder="ADMIN_API_KEY"
                prop:value=api_key
                on:input=move |ev| {
                    let v = event_target_value(&ev);
                    crate::actions::save_admin_api_key(&v);
                    api_key.set(v);
                }
            />

            <div class="flex items-center gap-3 mb-4">
                <button
                    class="text-xs px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800"
                    on:click={
                        let s = signals.clone();
                        move |_: MouseEvent| {
                            crate::actions::refresh_pending_registrations(s.clone(), api_key.get_untracked());
                        }
                    }
                >
                    "Refresh"
                </button>
                <span class="text-sm text-slate-400">
                    {move || match (pending.get(), pending_error.get()) {
                        (_, Some(e)) => format!("Error: {e}"),
                        (Some(n), None) => format!("{n} commitment(s) pending"),
                        (None, None) => "Pending count not loaded.".to_string(),
                    }}
                </span>
            </div>

            <button
                class="w-full py-3 rounded-lg bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium transition"
                disabled=is_building()
                on:click={
                    let s = signals.clone();
                    move |_: MouseEvent| {
                        crate::actions::build_whitelist_from_registrations(s.clone(), api_key.get_untracked());
                    }
                }
            >
                {move || if is_building() { "Building whitelist..." } else { "Build Whitelist From Pending Registrations" }}
            </button>

            {move || {
                let b = build.get();
                match b.phase {
                    WhitelistBuildPhase::Done => {
                        let root = b.merkle_root.unwrap_or_default();
                        let count = b.commitment_count.unwrap_or_default();
                        view! {
                            <div class="mt-4 p-3 rounded-lg bg-emerald-900/30 border border-emerald-800 text-emerald-200 text-sm">
                                "Whitelist built from " {count} " voter(s). Root copied into the form below: "
                                <span class="font-mono break-all">{root}</span>
                            </div>
                        }.into_view()
                    }
                    WhitelistBuildPhase::Failed => {
                        let msg = b.message.unwrap_or_else(|| "Unknown error".into());
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

/// Form for `createPoll(merkleRoot, numOptions, deadline, metadataUri)`.
#[component]
fn CreatePollForm(#[prop(into)] signals: AppSignals, merkle_root: RwSignal<String>) -> impl IntoView {
    let tx = signals.admin_create;

    let num_options = create_rw_signal(String::from("2"));
    let deadline = create_rw_signal(String::new());
    let metadata_uri = create_rw_signal(String::new());

    let is_busy = move || tx.get().phase == AdminTxPhase::Submitting;

    let on_submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        crate::actions::submit_create_poll(
            signals.clone(),
            merkle_root.get_untracked(),
            num_options.get_untracked(),
            deadline.get_untracked(),
            metadata_uri.get_untracked(),
        );
    };

    view! {
        <form class="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-6" on:submit=on_submit>
            <h3 class="text-sm font-medium text-slate-300 mb-4">"Create Poll"</h3>

            <label class="block text-xs text-slate-400 mb-1">"Merkle root (0x… 32 bytes)"</label>
            <input
                class="w-full mb-3 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm font-mono"
                placeholder="0x..."
                prop:value=merkle_root
                on:input=move |ev| merkle_root.set(event_target_value(&ev))
            />

            <label class="block text-xs text-slate-400 mb-1">"Number of options"</label>
            <input
                class="w-full mb-3 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm"
                type="number"
                min="2"
                prop:value=num_options
                on:input=move |ev| num_options.set(event_target_value(&ev))
            />

            <label class="block text-xs text-slate-400 mb-1">"Voting deadline"</label>
            <input
                class="w-full mb-3 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm"
                type="datetime-local"
                prop:value=deadline
                on:input=move |ev| deadline.set(event_target_value(&ev))
            />

            <label class="block text-xs text-slate-400 mb-1">"Poll question / description"</label>
            <input
                class="w-full mb-4 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm"
                placeholder="e.g. Should we adopt proposal X? (Yes / No)"
                prop:value=metadata_uri
                on:input=move |ev| metadata_uri.set(event_target_value(&ev))
            />

            <button
                type="submit"
                class="w-full py-3 rounded-lg bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium transition"
                disabled=is_busy()
            >
                {move || match tx.get().phase {
                    AdminTxPhase::Submitting => "Awaiting wallet confirmation...",
                    _ => "Create Poll",
                }}
            </button>

            <AdminTxFeedback tx=tx success_prefix="Poll creation broadcast! Tx: " />
        </form>
    }
}

/// The existing polls, each with a "Close" action (owner-only, on-chain
/// `onlyOwner` is the real guard — this is just the UI).
#[component]
fn ManagePolls(#[prop(into)] signals: AppSignals) -> impl IntoView {
    let polls = signals.polls;
    let tx = signals.admin_close;

    view! {
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6">
            <h3 class="text-sm font-medium text-slate-300 mb-4">"Manage Polls"</h3>

            {move || {
                let Some(list) = polls.get() else {
                    return view! { <div class="viche-shimmer h-16 rounded-lg"></div> }.into_view();
                };
                if list.is_empty() {
                    return view! {
                        <div class="text-slate-500 text-sm">"No polls have been created yet."</div>
                    }.into_view();
                }
                list.iter().map(|p| {
                    let poll_id = p.poll_id.to_string();
                    let active = p.active;
                    let pid_for_click = poll_id.clone();
                    let s = signals.clone();
                    let is_busy = move || tx.get().phase == AdminTxPhase::Submitting;

                    view! {
                        <div class="flex items-center justify-between py-2 border-b border-slate-800 last:border-0">
                            <span class="text-sm text-slate-300">"Poll #" {poll_id.clone()}</span>
                            <button
                                class="text-xs px-3 py-1.5 rounded-lg border border-red-800 text-red-300 hover:bg-red-900/30 disabled:opacity-40 disabled:cursor-not-allowed"
                                disabled=move || !active || is_busy()
                                on:click=move |_: MouseEvent| {
                                    crate::actions::submit_close_poll(s.clone(), pid_for_click.clone());
                                }
                            >
                                {if active { "Close" } else { "Closed" }}
                            </button>
                        </div>
                    }
                }).collect::<Vec<_>>().into_view()
            }}

            <AdminTxFeedback tx=tx success_prefix="Close broadcast! Tx: " />
        </div>
    }
}

/// Shared success/error banner for an [`crate::state::AdminTxState`] signal.
#[component]
fn AdminTxFeedback(
    tx: RwSignal<crate::state::AdminTxState>,
    success_prefix: &'static str,
) -> impl IntoView {
    view! {
        {move || {
            let s = tx.get();
            match s.phase {
                AdminTxPhase::Done => {
                    let hash = s.tx_hash.unwrap_or_default();
                    view! {
                        <div class="mt-4 p-3 rounded-lg bg-emerald-900/30 border border-emerald-800 text-emerald-200 text-sm">
                            {success_prefix}
                            <span class="font-mono break-all">{hash}</span>
                        </div>
                    }.into_view()
                }
                AdminTxPhase::Failed => {
                    let msg = s.message.unwrap_or_else(|| "Unknown error".into());
                    view! {
                        <div class="mt-4 p-3 rounded-lg bg-red-900/30 border border-red-800 text-red-200 text-sm">
                            {msg}
                        </div>
                    }.into_view()
                }
                _ => view! { <span></span> }.into_view(),
            }
        }}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::next_tick;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_test::*;

    /// Mount `<AdminPage>` into a fresh, detached `<div>` (never attached to
    /// the visible document) and return it so the test can read back
    /// rendered text. Leptos updates this element reactively as `signals`
    /// change, same as it would for a real mount.
    fn mount(signals: AppSignals) -> web_sys::HtmlElement {
        let document = web_sys::window().unwrap().document().unwrap();
        let container = document
            .create_element("div")
            .unwrap()
            .dyn_into::<web_sys::HtmlElement>()
            .unwrap();

        let mount_signals = signals.clone();
        leptos::mount_to(container.clone(), move || {
            view! { <AdminPage signals=mount_signals.clone() /> }
        });
        container
    }

    #[wasm_bindgen_test]
    async fn shows_connect_prompt_when_wallet_is_disconnected() {
        let signals = AppSignals::new();
        let container = mount(signals);
        next_tick().await;

        let text = container.text_content().unwrap_or_default();
        assert!(
            text.contains("Connect the poll-admin wallet"),
            "unexpected content: {text}"
        );
        assert!(!text.contains("Create Poll"));
    }

    #[wasm_bindgen_test]
    async fn shows_not_administrator_message_for_a_connected_non_owner() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xSomeone".to_string(), "0x1".to_string());
        // is_admin defaults to false.
        let container = mount(signals);
        next_tick().await;

        let text = container.text_content().unwrap_or_default();
        assert!(
            text.contains("not the poll administrator"),
            "unexpected content: {text}"
        );
        assert!(!text.contains("Create Poll"));
    }

    #[wasm_bindgen_test]
    async fn shows_create_and_manage_sections_for_the_owner_wallet() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xOwner".to_string(), "0x1".to_string());
        signals.is_admin.set(true);
        let container = mount(signals);
        next_tick().await;

        let text = container.text_content().unwrap_or_default();
        assert!(text.contains("Create Poll"), "unexpected content: {text}");
        assert!(text.contains("Manage Polls"), "unexpected content: {text}");
        assert!(!text.contains("not the poll administrator"));
        assert!(!text.contains("Connect the poll-admin wallet"));
    }

    #[wasm_bindgen_test]
    async fn gate_reacts_when_is_admin_flips_after_mount() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xOwner".to_string(), "0x1".to_string());
        // Mount while still not (yet) confirmed as admin.
        let container = mount(signals.clone());
        next_tick().await;
        assert!(container
            .text_content()
            .unwrap_or_default()
            .contains("not the poll administrator"));

        // check_admin (or a direct set, as here) resolving later should
        // reactively flip the gate without remounting.
        signals.is_admin.set(true);
        next_tick().await;
        let text = container.text_content().unwrap_or_default();
        assert!(text.contains("Create Poll"), "unexpected content: {text}");
    }
}
