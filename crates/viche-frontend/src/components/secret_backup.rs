//! The "Voting secret" panel: see it, back it up, restore it, forget it.
//!
//! A voter's secret used to be invisible. It was generated on first use,
//! written to `localStorage`, and never shown — so there was no way to copy it
//! to a second device, no way to notice a failed write, and no way to recover
//! from a cleared browser. This panel is the whole recovery story:
//!
//! * **Export** — reveals the secret as a JSON backup blob the voter can put
//!   in a password manager.
//! * **Import** — restores one, on any device, into the connected account.
//! * **Migrate** — the explicit, warned switch from a legacy random secret to
//!   the wallet-derived scheme (see [`crate::secret`]).
//! * **Forget** — drops the local cache.
//!
//! The secret is hidden behind a reveal toggle rather than rendered on load.
//! Anyone who reads it off the screen can vote as this voter in every poll
//! their commitment is in, and the panel sits on a page voters are told to
//! open — screen sharing and shoulder surfing are the realistic threats, so
//! the default is "not on screen".

use leptos::*;
use web_sys::MouseEvent;

use crate::secret::SecretOrigin;
use crate::state::AppSignals;

/// Backup / restore controls for the connected account's voting secret.
#[component]
pub fn SecretBackupPanel(#[prop(into)] signals: AppSignals) -> impl IntoView {
    let wallet = signals.wallet;
    let secret = signals.secret;

    // Local to the panel: the paste box never belongs in global state.
    let import_input = create_rw_signal(String::new());

    let is_busy = move || secret.get().busy;

    view! {
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 mt-6">
            <h3 class="text-sm font-medium text-slate-300 mb-1">"Your voting secret"</h3>
            <p class="text-xs text-slate-500 mb-4">
                "This value is your ballot. Anyone who has it can vote as you; if you lose it "
                "and cannot re-derive it, your registration is dead weight and your vote is "
                "gone. Back it up."
            </p>

            {move || {
                if wallet.get().address.is_none() {
                    return view! {
                        <div class="text-slate-400 text-sm">
                            "Connect your wallet to view or restore your voting secret."
                        </div>
                    }.into_view();
                }

                let s = secret.get();
                let load_signals = signals.clone();
                let migrate_signals = signals.clone();
                let forget_signals = signals.clone();
                let import_signals = signals.clone();

                view! {
                    <div>
                        <ProvenanceNotice origin=s.origin />

                        {s.storage_warning.clone().map(|w| view! {
                            // The banner that exists because the old code did
                            // `let _ = local_storage_set(...)`. A failed cache
                            // write is now impossible to miss.
                            <div class="mb-4 p-3 rounded-lg bg-amber-900/30 border border-amber-700 text-amber-100 text-sm">
                                <strong class="block mb-1">"Your secret was not saved in this browser."</strong>
                                {w}
                            </div>
                        })}

                        {s.error.clone().map(|e| view! {
                            <div class="mb-4 p-3 rounded-lg bg-red-900/30 border border-red-800 text-red-200 text-sm">
                                {e}
                            </div>
                        })}

                        {s.notice.clone().map(|n| view! {
                            <div class="mb-4 p-3 rounded-lg bg-emerald-900/30 border border-emerald-800 text-emerald-200 text-sm">
                                {n}
                            </div>
                        })}

                        {match s.value.clone() {
                            None => view! {
                                <button
                                    class="w-full py-3 rounded-lg bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium transition"
                                    disabled=is_busy()
                                    on:click=move |_: MouseEvent| {
                                        crate::actions::load_secret(load_signals.clone());
                                    }
                                >
                                    {move || if is_busy() {
                                        "Waiting for your wallet signature..."
                                    } else {
                                        "Unlock my voting secret"
                                    }}
                                </button>
                            }.into_view(),
                            Some(_) => {
                                let address = wallet.get().address.unwrap_or_default();
                                view! {
                                    <ExportBox signals=signals.clone() address=address />
                                }.into_view()
                            }
                        }}

                        {(s.origin.is_some_and(|o| !o.is_recoverable_from_wallet())).then(|| view! {
                            <MigrateBox signals=migrate_signals.clone() busy=is_busy() />
                        })}

                        <div class="mt-6 pt-6 border-t border-slate-800">
                            <label class="block text-xs text-slate-400 mb-1">
                                "Restore from a backup"
                            </label>
                            <p class="text-xs text-slate-500 mb-2">
                                "Paste an exported backup (or a bare secret value). This replaces "
                                "the secret cached for the connected account."
                            </p>
                            <textarea
                                class="w-full mb-2 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-xs font-mono h-24"
                                placeholder="{ \"viche_backup\": 1, ... }"
                                prop:value=import_input
                                on:input=move |ev| import_input.set(event_target_value(&ev))
                            ></textarea>
                            <div class="flex items-center gap-3">
                                <button
                                    class="text-xs px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 disabled:opacity-40"
                                    disabled=is_busy()
                                    on:click=move |_: MouseEvent| {
                                        crate::actions::import_secret(
                                            import_signals.clone(),
                                            import_input.get_untracked(),
                                        );
                                        import_input.set(String::new());
                                    }
                                >
                                    "Import secret"
                                </button>
                                <button
                                    class="text-xs px-3 py-1.5 rounded-lg border border-red-800 text-red-300 hover:bg-red-900/30 disabled:opacity-40"
                                    disabled=is_busy()
                                    on:click=move |_: MouseEvent| {
                                        crate::actions::forget_secret(forget_signals.clone());
                                    }
                                >
                                    "Forget cached secret"
                                </button>
                            </div>
                        </div>
                    </div>
                }.into_view()
            }}
        </div>
    }
}

/// Explains where the current secret came from, and how badly the voter needs
/// a backup as a result.
#[component]
fn ProvenanceNotice(origin: Option<SecretOrigin>) -> impl IntoView {
    view! {
        {move || match origin {
            None => view! {
                <div class="mb-4 p-3 rounded-lg bg-slate-800/60 border border-slate-700 text-slate-300 text-sm">
                    "Not unlocked yet this session."
                </div>
            }.into_view(),
            Some(o) => {
                // Only the wallet-derived case is safe to present calmly:
                // the others are one cleared browser away from being gone.
                let classes = if o.is_recoverable_from_wallet() {
                    "mb-4 p-3 rounded-lg bg-slate-800/60 border border-slate-700 text-slate-300 text-sm"
                } else {
                    "mb-4 p-3 rounded-lg bg-amber-900/30 border border-amber-700 text-amber-100 text-sm"
                };
                let title = match o {
                    SecretOrigin::WalletDerivedV1 => "Wallet-derived secret",
                    SecretOrigin::LegacyRandom => "Legacy secret - back this up now",
                    SecretOrigin::Imported => "Restored secret - keep your backup",
                };
                view! {
                    <div class=classes>
                        <strong class="block mb-1">{title}</strong>
                        {o.description()}
                    </div>
                }.into_view()
            }
        }}
    }
}

/// The reveal-and-copy half of the panel.
#[component]
fn ExportBox(#[prop(into)] signals: AppSignals, address: String) -> impl IntoView {
    let secret = signals.secret;
    let revealed = move || secret.get().revealed;

    // Rebuilt on each render from the *current* signal contents rather than
    // captured once, so a migrate or import updates the blob in place.
    let blob = move || {
        let s = secret.get();
        let (Some(v), Some(origin)) = (s.value.clone(), s.origin) else {
            return String::new();
        };
        let parsed = alloy_primitives::U256::from_str_radix(&v, 10).unwrap_or_default();
        crate::secret::backup_blob(
            &address,
            &crate::secret::VoterSecret {
                value: parsed,
                origin,
                storage_warning: None,
            },
        )
    };

    view! {
        <div>
            <div class="flex items-center justify-between mb-2">
                <label class="block text-xs text-slate-400">"Backup"</label>
                <button
                    class="text-xs px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800"
                    on:click=move |_: MouseEvent| {
                        secret.update(|s| s.revealed = !s.revealed);
                    }
                >
                    {move || if revealed() { "Hide" } else { "Reveal" }}
                </button>
            </div>

            {move || if revealed() {
                view! {
                    <div>
                        <textarea
                            class="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-xs font-mono h-36"
                            readonly=true
                            prop:value=blob()
                        ></textarea>
                        <p class="text-xs text-amber-200/80 mt-2">
                            "Store this in a password manager. Do not paste it into a chat, an "
                            "email, or any site that is not Viche - it is enough on its own to "
                            "cast your ballot."
                        </p>
                    </div>
                }.into_view()
            } else {
                view! {
                    <div class="px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-xs font-mono text-slate-500">
                        "\u{2022}".repeat(48)
                    </div>
                }.into_view()
            }}
        </div>
    }
}

/// The explicit opt-in to the wallet-derived scheme, for voters carrying a
/// legacy or imported secret.
#[component]
fn MigrateBox(#[prop(into)] signals: AppSignals, busy: bool) -> impl IntoView {
    view! {
        <div class="mt-6 p-3 rounded-lg bg-slate-800/60 border border-slate-700">
            <p class="text-xs text-slate-300 mb-2">
                <strong>"Switch to a wallet-derived secret?"</strong>
                " You would never need a backup again - it can always be re-derived from this "
                "wallet. But it is a "
                <strong>"different"</strong>
                " secret, so the commitment you already registered stops working: you must "
                "register again, and you cannot vote in a poll whose whitelist was built from "
                "the old one. Export your current secret first."
            </p>
            <button
                class="text-xs px-3 py-1.5 rounded-lg border border-amber-700 text-amber-200 hover:bg-amber-900/30 disabled:opacity-40"
                disabled=busy
                on:click=move |_: MouseEvent| {
                    crate::actions::migrate_secret_to_wallet_derived(signals.clone());
                }
            >
                "Switch to wallet-derived secret"
            </button>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::VoterSecret;
    use crate::storage::StorageError;
    use crate::test_support::next_tick;
    use alloy_primitives::U256;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_test::*;

    fn mount(signals: AppSignals) -> web_sys::HtmlElement {
        let document = web_sys::window().unwrap().document().unwrap();
        let container = document
            .create_element("div")
            .unwrap()
            .dyn_into::<web_sys::HtmlElement>()
            .unwrap();
        let mount_signals = signals.clone();
        leptos::mount_to(container.clone(), move || {
            view! { <SecretBackupPanel signals=mount_signals.clone() /> }
        });
        container
    }

    fn resolved(value: u64, origin: SecretOrigin) -> VoterSecret {
        VoterSecret {
            value: U256::from(value),
            origin,
            storage_warning: None,
        }
    }

    #[wasm_bindgen_test]
    async fn prompts_to_connect_when_no_wallet_is_attached() {
        let container = mount(AppSignals::new());
        next_tick().await;
        let text = container.text_content().unwrap_or_default();
        assert!(text.contains("Connect your wallet"), "unexpected: {text}");
    }

    #[wasm_bindgen_test]
    async fn offers_to_unlock_before_the_secret_is_resolved() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xVoter".into(), "0x1".into());
        let container = mount(signals);
        next_tick().await;
        let text = container.text_content().unwrap_or_default();
        assert!(text.contains("Unlock my voting secret"), "unexpected: {text}");
    }

    #[wasm_bindgen_test]
    async fn keeps_the_secret_hidden_until_reveal_is_pressed() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xVoter".into(), "0x1".into());
        signals.secret_resolved(&resolved(123_456_789, SecretOrigin::WalletDerivedV1));
        let container = mount(signals.clone());
        next_tick().await;

        // The value must not be anywhere in the DOM text while hidden.
        let text = container.text_content().unwrap_or_default();
        assert!(!text.contains("123456789"), "secret leaked while hidden: {text}");
        assert!(text.contains("Reveal"), "unexpected: {text}");

        signals.secret.update(|s| s.revealed = true);
        next_tick().await;
        // Revealed, the blob lives in a textarea's `value` property rather
        // than its text content, so read it off the element.
        let area = container
            .query_selector("textarea")
            .unwrap()
            .unwrap()
            .dyn_into::<web_sys::HtmlTextAreaElement>()
            .unwrap();
        assert!(area.value().contains("123456789"), "blob missing the secret");
        assert!(area.value().contains("wallet-derived-v1"));
    }

    #[wasm_bindgen_test]
    async fn shows_the_storage_warning_prominently() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xVoter".into(), "0x1".into());
        signals.secret_resolved(&VoterSecret {
            value: U256::from(7u64),
            origin: SecretOrigin::WalletDerivedV1,
            storage_warning: Some(StorageError::QuotaExceeded {
                area: "localStorage",
            }),
        });
        let container = mount(signals);
        next_tick().await;

        let text = container.text_content().unwrap_or_default();
        assert!(
            text.contains("was not saved in this browser"),
            "storage failure not surfaced: {text}"
        );
        assert!(text.contains("full"), "quota detail missing: {text}");
    }

    #[wasm_bindgen_test]
    async fn warns_about_a_legacy_secret_and_offers_the_explicit_migration() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xVoter".into(), "0x1".into());
        signals.secret_resolved(&resolved(42, SecretOrigin::LegacyRandom));
        let container = mount(signals);
        next_tick().await;

        let text = container.text_content().unwrap_or_default();
        assert!(text.contains("Legacy secret"), "unexpected: {text}");
        assert!(
            text.contains("Switch to wallet-derived secret"),
            "no migration offered: {text}"
        );
        // The migration must state the consequence, not just offer a button.
        assert!(text.contains("register again"), "unexpected: {text}");
    }

    #[wasm_bindgen_test]
    async fn does_not_offer_migration_for_an_already_derived_secret() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xVoter".into(), "0x1".into());
        signals.secret_resolved(&resolved(42, SecretOrigin::WalletDerivedV1));
        let container = mount(signals);
        next_tick().await;

        let text = container.text_content().unwrap_or_default();
        assert!(!text.contains("Switch to wallet-derived secret"), "unexpected: {text}");
    }

    #[wasm_bindgen_test]
    async fn surfaces_errors_and_notices() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xVoter".into(), "0x1".into());
        let container = mount(signals.clone());
        next_tick().await;

        signals.secret_failed("wallet said no");
        next_tick().await;
        assert!(container
            .text_content()
            .unwrap_or_default()
            .contains("wallet said no"));

        signals.secret_notice("all good");
        next_tick().await;
        let text = container.text_content().unwrap_or_default();
        assert!(text.contains("all good"), "unexpected: {text}");
        assert!(!text.contains("wallet said no"), "stale error kept: {text}");
    }
}
