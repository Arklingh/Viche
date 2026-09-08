//! Voter registration page — submit an identity commitment ahead of the
//! next poll.
//!
//! A poll's whitelist is a fixed Merkle root chosen when it's created — the
//! contract has no way to add members afterwards. So voters register here
//! *before* the admin builds the next poll (see [`crate::components::admin`]
//! for the admin side of this flow), and the relayer holds the commitment
//! list until the admin locks it into a poll.

use leptos::*;

use crate::state::{AppSignals, RegisterPhase};

/// The "Register to Vote" page.
#[component]
pub fn RegisterPage(#[prop(into)] signals: AppSignals) -> impl IntoView {
    let wallet = signals.wallet;
    let register = signals.register;

    let is_busy = move || register.get().phase == RegisterPhase::Submitting;

    view! {
        <section class="max-w-2xl mx-auto px-4 py-8">
            <h2 class="text-2xl font-semibold mb-2">"Register to Vote"</h2>
            <p class="text-sm text-slate-400 mb-6">
                "Submit your identity commitment now so the poll admin can include you in "
                "the next poll's whitelist. Your secret never leaves this browser — only its "
                "one-way hash is sent."
            </p>

            {move || {
                if wallet.get().address.is_none() {
                    view! {
                        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 text-slate-400 text-sm">
                            "Connect your wallet to register."
                        </div>
                    }.into_view()
                } else {
                    let click_signals = signals.clone();
                    view! {
                        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6">
                            <button
                                class="w-full py-3 rounded-lg bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium transition"
                                disabled=is_busy()
                                on:click=move |_| crate::actions::register_to_vote(click_signals.clone())
                            >
                                {move || if is_busy() { "Registering..." } else { "Register to Vote" }}
                            </button>

                            {move || {
                                let r = register.get();
                                match r.phase {
                                    RegisterPhase::Done => {
                                        let total = r.total_pending.unwrap_or_default();
                                        view! {
                                            <div class="mt-4 p-3 rounded-lg bg-emerald-900/30 border border-emerald-800 text-emerald-200 text-sm">
                                                "Registered! "
                                                {total} " commitment(s) are currently pending for the next poll."
                                            </div>
                                        }.into_view()
                                    }
                                    RegisterPhase::Failed => {
                                        let msg = r.message.unwrap_or_else(|| "Unknown error".into());
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
                    }.into_view()
                }
            }}
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::next_tick;
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
            view! { <RegisterPage signals=mount_signals.clone() /> }
        });
        container
    }

    #[wasm_bindgen_test]
    async fn shows_connect_prompt_when_wallet_is_disconnected() {
        let signals = AppSignals::new();
        let container = mount(signals);
        next_tick().await;

        let text = container.text_content().unwrap_or_default();
        assert!(text.contains("Connect your wallet to register"));
        assert!(!text.contains("Register to Vote"));
    }

    #[wasm_bindgen_test]
    async fn shows_register_button_when_wallet_is_connected() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xVoter".to_string(), "0x1".to_string());
        let container = mount(signals);
        next_tick().await;

        let text = container.text_content().unwrap_or_default();
        assert!(text.contains("Register to Vote"), "unexpected content: {text}");
    }

    #[wasm_bindgen_test]
    async fn shows_success_message_after_registration_completes() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xVoter".to_string(), "0x1".to_string());
        let container = mount(signals.clone());
        next_tick().await;

        signals.register_done(3);
        next_tick().await;

        let text = container.text_content().unwrap_or_default();
        assert!(text.contains("Registered!"), "unexpected content: {text}");
        assert!(text.contains('3'), "unexpected content: {text}");
    }

    #[wasm_bindgen_test]
    async fn shows_error_message_on_failure() {
        let signals = AppSignals::new();
        signals.wallet_connected("0xVoter".to_string(), "0x1".to_string());
        let container = mount(signals.clone());
        next_tick().await;

        signals.register_failed("Connect your wallet first.");
        next_tick().await;

        let text = container.text_content().unwrap_or_default();
        assert!(text.contains("Connect your wallet first."), "unexpected content: {text}");
    }
}
