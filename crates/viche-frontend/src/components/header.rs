//! Top navigation bar with brand + wallet connection status.

use leptos::*;
use web_sys::MouseEvent;

use crate::state::{AppSignals, View};

/// The app header.
#[component]
pub fn Header(#[prop(into)] signals: AppSignals) -> impl IntoView {
    let wallet = signals.wallet;
    let is_admin = signals.is_admin;
    let view_signal = signals.view;

    view! {
        <header class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-10">
            <div class="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
                <button
                    class="flex items-center gap-2"
                    on:click=move |_| view_signal.set(View::List)
                >
                    <span class="text-2xl" aria-hidden="true">"\u{1F5F3}\u{FE0F}"</span>
                    <h1 class="text-xl font-semibold tracking-tight">
                        <span class="text-brand-400">"Vi"</span>"che"
                    </h1>
                    <span class="ml-2 text-xs text-slate-500 hidden sm:inline">
                        "anonymous voting"
                    </span>
                </button>

                <div class="flex items-center gap-3">
                    {move || is_admin.get().then(|| view! {
                        <button
                            class="text-sm px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800"
                            on:click=move |_| view_signal.set(View::Admin)
                        >
                            "Admin"
                        </button>
                    })}

                    {move || {
                        let w = wallet.get();
                        if w.connecting {
                            view! {
                                <span class="text-sm text-slate-400 animate-pulse">"Connecting..."</span>
                            }.into_view()
                        } else if let Some(addr) = &w.address {
                            view! {
                                <span
                                    class="text-sm font-mono px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700"
                                    title=addr.clone()
                                >
                                    {shorten(addr)}
                                </span>
                                <span class="text-xs text-slate-500">
                                    {w.chain_id.clone().unwrap_or_default()}
                                </span>
                            }.into_view()
                        } else {
                            view! {
                                <span class="text-sm text-slate-500">"not connected"</span>
                            }.into_view()
                        }
                    }}

                    <ConnectButton signals=signals.clone() />
                </div>
            </div>

            {move || {
                let w = wallet.get();
                w.error.map(|e| view! {
                    <div class="bg-red-900/40 border-t border-red-800 text-red-200 text-sm px-4 py-2 text-center">
                        {e}
                    </div>
                })
            }}
        </header>
    }
}

/// The connect / disconnect button.
#[component]
fn ConnectButton(#[prop(into)] signals: AppSignals) -> impl IntoView {
    let wallet = signals.wallet;
    let is_admin = signals.is_admin;

    view! {
        {move || {
            let w = wallet.get();
            if w.address.is_some() {
                let wallet_for_click = wallet;
                view! {
                    <button
                        class="text-sm px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800"
                        on:click=move |_: MouseEvent| {
                            wallet_for_click.update(|w| {
                                w.address = None;
                                w.error = None;
                            });
                            is_admin.set(false);
                        }
                    >
                        "Disconnect"
                    </button>
                }.into_view()
            } else {
                let signals_for_click = signals.clone();
                view! {
                    <button
                        class="text-sm px-3 py-1.5 rounded-lg bg-brand-600 hover:bg-brand-500 text-white font-medium transition"
                        on:click=move |_: MouseEvent| {
                            signals_for_click.wallet_connecting();
                            crate::actions::connect_wallet(signals_for_click.clone());
                        }
                        disabled=w.connecting
                    >
                        "Connect Wallet"
                    </button>
                }.into_view()
            }
        }}
    }
}

/// Truncate `0x1234...abcd` for display.
fn shorten(addr: &str) -> String {
    let len = addr.len();
    if len <= 10 {
        return addr.to_string();
    }
    format!("{}...{}", &addr[..6], &addr[len - 4..])
}
