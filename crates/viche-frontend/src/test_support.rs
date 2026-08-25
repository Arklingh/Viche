//! Shared test-only helpers: a mock EIP-1193 `window.ethereum` provider and
//! small async utilities for driving `spawn_local`-scheduled work to
//! completion inside `#[wasm_bindgen_test]`s.
//!
//! Only compiled under `#[cfg(test)]`; never part of the shipped bundle.

#![cfg(test)]

use wasm_bindgen::prelude::*;

// Declared exactly once for the whole test binary (per wasm-bindgen-test's
// own rule): several tests here touch `window`/`document`, which Node.js
// doesn't provide, so the whole suite runs in a headless browser instead.
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

/// Install a mock `window.ethereum` whose `request({method, params})` runs
/// the given JS body (with `method` and `params` in scope). The body must
/// `return` a value or a `Promise`, mirroring the real EIP-1193 provider.
pub fn install_mock_ethereum(request_body: &str, is_metamask: bool) {
    let window = web_sys::window().expect("no window in test env");
    let ethereum = js_sys::Object::new();

    let full_body = format!(
        "const method = req.method; const params = req.params; {}",
        request_body
    );
    let request_fn = js_sys::Function::new_with_args("req", &full_body);
    js_sys::Reflect::set(&ethereum, &"request".into(), &request_fn).unwrap();
    js_sys::Reflect::set(&ethereum, &"isMetaMask".into(), &JsValue::from_bool(is_metamask))
        .unwrap();
    // `.on(event, cb)` is called unconditionally by on_accounts_changed /
    // on_chain_changed; give the mock a harmless no-op so those don't panic.
    let on_fn = js_sys::Function::new_no_args("");
    js_sys::Reflect::set(&ethereum, &"on".into(), &on_fn).unwrap();

    js_sys::Reflect::set(&window, &"ethereum".into(), &ethereum).unwrap();
}

/// Remove any mock `window.ethereum`, restoring the "no wallet" state.
pub fn remove_mock_ethereum() {
    let window = web_sys::window().expect("no window in test env");
    let _ = js_sys::Reflect::delete_property(&window, &"ethereum".into());
}

/// Set a `window.<key>` global string, mirroring how `config.rs` reads
/// runtime overrides (`__VICHE_VOTING_MANAGER_ADDRESS__` etc).
pub fn set_global_string(key: &str, value: &str) {
    let window = web_sys::window().expect("no window in test env");
    js_sys::Reflect::set(&window, &key.into(), &value.into()).unwrap();
}

/// Remove a `window.<key>` global previously set by [`set_global_string`].
pub fn remove_global(key: &str) {
    let window = web_sys::window().expect("no window in test env");
    let _ = js_sys::Reflect::delete_property(&window, &key.into());
}

/// Yield control back to the JS event loop for one macrotask (`setTimeout`
/// 0ms), letting any pending `spawn_local` futures make progress.
pub async fn next_tick() {
    let window = web_sys::window().expect("no window in test env");
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        window
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 0)
            .expect("set_timeout failed");
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// Poll `cond` once per macrotask until it's `true` or `max_ticks` elapse.
/// Returns the final value of `cond()`. Used to wait for a `spawn_local`
/// task (e.g. a mocked wallet round-trip) to settle a signal.
pub async fn wait_until<F: Fn() -> bool>(cond: F, max_ticks: u32) -> bool {
    for _ in 0..max_ticks {
        if cond() {
            return true;
        }
        next_tick().await;
    }
    cond()
}

// ---- global-mock serialization ------------------------------------------
//
// wasm-bindgen-test interleaves `async fn` tests cooperatively on the single
// wasm thread rather than running them strictly one-at-a-time: several tests
// can be mid-`.await` at once. Since `window.ethereum` and the
// `window.__VICHE_*__` config globals are process-wide, two interleaved
// tests that each install their own mock provider can stomp on each other.
// Every test that touches those globals must hold this lock for its whole
// body so installs/mutations/removals never interleave across tests.

thread_local! {
    static GLOBAL_MOCK_LOCK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// RAII guard releasing [`lock_global_mocks`] when dropped (including on
/// test panic, since Rust still unwinds/drops locals through a `panic!`).
pub struct GlobalMockGuard {
    _private: (),
}

impl Drop for GlobalMockGuard {
    fn drop(&mut self) {
        GLOBAL_MOCK_LOCK.with(|l| l.set(false));
    }
}

/// Acquire the process-wide "I'm about to touch `window.ethereum` / the
/// `__VICHE_*__` globals" lock, waiting a macrotask at a time if another
/// interleaved test currently holds it. Hold the returned guard for the
/// entire duration your test's mock needs to stay installed.
pub async fn lock_global_mocks() -> GlobalMockGuard {
    loop {
        let acquired = GLOBAL_MOCK_LOCK.with(|l| {
            if l.get() {
                false
            } else {
                l.set(true);
                true
            }
        });
        if acquired {
            return GlobalMockGuard { _private: () };
        }
        next_tick().await;
    }
}
