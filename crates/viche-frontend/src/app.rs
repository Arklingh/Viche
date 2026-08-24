//! Root component — holds the shared [`AppSignals`] and routes between views.

use leptos::*;

use crate::components::{AdminPage, Header, PollDetail, PollList};
use crate::state::{AppSignals, View};

/// The application root. Mounted once into `<body>` from [`crate::lib_main`].
#[component]
pub fn App() -> impl IntoView {
    // One signal bag, shared via context so children don't need prop drilling.
    let signals = AppSignals::new();
    provide_context(signals.clone());

    let view = signals.view;

    view! {
        <div class="min-h-screen flex flex-col">
            <Header signals=signals.clone() />
            <main class="flex-1">
                {move || match view.get() {
                    View::List => view! { <PollList signals=signals.clone() /> }.into_view(),
                    View::Detail(id) => view! {
                        <PollDetail signals=signals.clone() poll_id=id />
                    }.into_view(),
                    View::Admin => view! {
                        <AdminPage signals=signals.clone() />
                    }.into_view(),
                }}
            </main>
            <Footer />
        </div>
    }
}

/// The footer with a one-line privacy reminder.
#[component]
fn Footer() -> impl IntoView {
    view! {
        <footer class="border-t border-slate-800 py-4 text-center text-xs text-slate-600">
            "🔒 Your secret never leaves the browser. Proofs are generated client-side."
        </footer>
    }
}
