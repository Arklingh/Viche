//! EIP-1193 wallet bridge.
//!
//! Talks to the injected `window.ethereum` provider (MetaMask, Rabby, etc.)
//! via raw `wasm-bindgen` bindings. We deliberately do not pull in an
//! `ethers-rs`/`alloy` WASM signer — the only thing the wallet does is
//! authenticate the *voter's session*. The actual vote signature never comes
//! from the wallet: the relayer signs and pays gas. The ZK proof, not an
//! ECDSA signature, is what authorises the ballot.
//!
//! Why connect the wallet at all, then?
//!   * It gives the UI a stable identity to key local storage (the voter's
//!     `secret`) against, so a user doesn't accidentally vote with someone
//!     else's secret on a shared machine.
//!   * Future work: signing a message with the wallet to register an identity
//!     commitment on-chain (out of scope for viche v1, where the admin
//!     pre-builds the Merkle tree).

use anyhow::{anyhow, Result};
use js_sys::{Array, Function, JsString, Promise};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// Wrapper around `window.ethereum` (the injected EIP-1193 provider).
#[derive(Clone)]
pub struct Wallet {
    inner: wasm_bindgen::JsValue,
}

/// Look up `window.ethereum` if an injected provider is present.
pub fn detect() -> Option<Wallet> {
    let win = web_sys::window()?;
    let ethereum = js_sys::Reflect::get(&win, &"ethereum".into()).ok()?;
    if ethereum.is_undefined() || ethereum.is_null() {
        return None;
    }
    Some(Wallet { inner: ethereum })
}

impl Wallet {
    /// Whether the detected provider identifies as MetaMask (cosmetic only).
    pub fn is_meta_mask(&self) -> bool {
        js_sys::Reflect::get(&self.inner, &"isMetaMask".into())
            .ok()
            .map(|v| v.as_bool().unwrap_or(false))
            .unwrap_or(false)
    }

    /// `eth_requestAccounts` — triggers the connect prompt.
    ///
    /// Returns the list of connected account addresses (hex strings).
    pub async fn request_accounts(&self) -> Result<Vec<String>> {
        let accounts = self
            .call("eth_requestAccounts", &[])
            .await
            .map_err(|e| anyhow!("wallet rejected connection: {:?}", e))?;

        let arr: Array = accounts
            .dyn_into()
            .map_err(|_| anyhow!("wallet returned a non-array from eth_requestAccounts"))?;
        Ok(arr
            .to_vec()
            .into_iter()
            .filter_map(|v| v.dyn_into::<JsString>().ok().map(|s| s.into()))
            .collect())
    }

    /// `eth_accounts` — accounts already authorised for this origin (no prompt).
    pub async fn accounts(&self) -> Result<Vec<String>> {
        let accounts = self
            .call("eth_accounts", &[])
            .await
            .map_err(|e| anyhow!("eth_accounts failed: {:?}", e))?;

        let arr: Array = accounts
            .dyn_into()
            .map_err(|_| anyhow!("wallet returned a non-array from eth_accounts"))?;
        Ok(arr
            .to_vec()
            .into_iter()
            .filter_map(|v| v.dyn_into::<JsString>().ok().map(|s| s.into()))
            .collect())
    }

    /// `eth_chainId` — the currently connected chain, as a `0x`-prefixed hex string.
    pub async fn chain_id(&self) -> Result<String> {
        let chain_id = self
            .call("eth_chainId", &[])
            .await
            .map_err(|e| anyhow!("eth_chainId failed: {:?}", e))?;
        let s: JsString = chain_id
            .dyn_into()
            .map_err(|_| anyhow!("wallet returned a non-string chain id"))?;
        Ok(s.into())
    }

    /// Register a JS callback for `accountsChanged`.
    pub fn on_accounts_changed<F>(&self, f: F) -> ClosureHandle
    where
        F: Fn(Vec<String>) + 'static,
    {
        let cb = Closure::new(move |args: JsValue| {
            if let Ok(arr) = args.dyn_into::<Array>() {
                let accounts = arr
                    .to_vec()
                    .into_iter()
                    .filter_map(|v| v.dyn_into::<JsString>().ok().map(|s| s.into()))
                    .collect();
                f(accounts);
            }
        });
        self.on("accountsChanged", cb.as_ref().unchecked_ref());
        ClosureHandle(cb)
    }

    /// Register a JS callback for `chainChanged`.
    pub fn on_chain_changed<F>(&self, f: F) -> ClosureHandle
    where
        F: Fn(String) + 'static,
    {
        let cb = Closure::new(move |args: JsValue| {
            if let Ok(s) = args.dyn_into::<JsString>() {
                f(s.into());
            }
        });
        self.on("chainChanged", cb.as_ref().unchecked_ref());
        ClosureHandle(cb)
    }

    /// Register an event listener on the provider.
    fn on(&self, event: &str, cb: &Function) {
        let this = &self.inner;
        let on_fn = js_sys::Reflect::get(this, &"on".into()).unwrap_or(JsValue::UNDEFINED);
        if let Ok(on_fn) = on_fn.dyn_into::<Function>() {
            let _ = on_fn.call2(this, &event.into(), cb);
        }
    }

    /// Call `provider.request({ method, params })` and `await` the Promise.
    async fn call(&self, method: &str, params: &[JsValue]) -> Result<JsValue, JsValue> {
        let req = js_sys::Object::new();
        js_sys::Reflect::set(&req, &"method".into(), &method.into())?;
        let params_arr = Array::new();
        for p in params {
            params_arr.push(p);
        }
        js_sys::Reflect::set(&req, &"params".into(), &params_arr)?;

        // provider.request(req) returns a Promise.
        let request_fn = js_sys::Reflect::get(&self.inner, &"request".into())?;
        let args = Array::new();
        args.push(req.as_ref());

        let promise_value = js_sys::Reflect::apply(
            &request_fn
                .dyn_into::<Function>()
                .map_err(|_| JsValue::from_str("request is not a function"))?,
            &self.inner,
            &args,
        )?;
        let promise: Promise = promise_value
            .dyn_into()
            .map_err(|_| JsValue::from_str("provider.request did not return a Promise"))?;

        wasm_bindgen_futures::JsFuture::from(promise).await
    }
}

/// A handle that keeps a `wasm-bindgen` [`Closure`] alive.
///
/// Dropping this drops the closure, which detaches the event listener (as
/// long as nothing else on the JS side retains a reference).
pub struct ClosureHandle(pub Closure<dyn FnMut(JsValue)>);

impl ClosureHandle {
    /// Forget the closure, leaking it permanently (listener never detaches).
    ///
    /// Useful for app-lifetime listeners where the bookkeeping isn't worth it.
    pub fn leak(self) {
        self.0.forget();
    }
}
