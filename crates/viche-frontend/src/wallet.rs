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

    /// `eth_call` — a read-only contract call, returning the raw ABI-encoded
    /// response bytes.
    pub async fn eth_call(&self, to: &str, data: &[u8]) -> Result<Vec<u8>> {
        let call_obj = js_sys::Object::new();
        js_sys::Reflect::set(&call_obj, &"to".into(), &to.into())
            .map_err(|_| anyhow!("failed to build eth_call params"))?;
        js_sys::Reflect::set(
            &call_obj,
            &"data".into(),
            &alloy_primitives::hex::encode_prefixed(data).into(),
        )
        .map_err(|_| anyhow!("failed to build eth_call params"))?;

        let result = self
            .call("eth_call", &[call_obj.into(), "latest".into()])
            .await
            .map_err(|e| anyhow!("eth_call failed: {:?}", e))?;

        let s: JsString = result
            .dyn_into()
            .map_err(|_| anyhow!("eth_call returned a non-string result"))?;
        let s: String = s.into();
        alloy_primitives::hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| anyhow!("eth_call returned invalid hex: {}", e))
    }

    /// `eth_sendTransaction` — sign and broadcast a transaction from the
    /// connected account. Returns the transaction hash once the wallet
    /// accepts it (does not wait for confirmation).
    pub async fn send_transaction(&self, from: &str, to: &str, data: &[u8]) -> Result<String> {
        let tx_obj = js_sys::Object::new();
        js_sys::Reflect::set(&tx_obj, &"from".into(), &from.into())
            .map_err(|_| anyhow!("failed to build transaction params"))?;
        js_sys::Reflect::set(&tx_obj, &"to".into(), &to.into())
            .map_err(|_| anyhow!("failed to build transaction params"))?;
        js_sys::Reflect::set(
            &tx_obj,
            &"data".into(),
            &alloy_primitives::hex::encode_prefixed(data).into(),
        )
        .map_err(|_| anyhow!("failed to build transaction params"))?;

        let result = self
            .call("eth_sendTransaction", &[tx_obj.into()])
            .await
            .map_err(|e| anyhow!("wallet rejected transaction: {:?}", e))?;

        let s: JsString = result
            .dyn_into()
            .map_err(|_| anyhow!("eth_sendTransaction returned a non-string result"))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{install_mock_ethereum, lock_global_mocks, remove_mock_ethereum};
    use wasm_bindgen_test::*;

    // `run_in_browser` is declared once, crate-wide, in `test_support`.
    //
    // Every test here holds the `lock_global_mocks` guard for its whole
    // body: wasm-bindgen-test interleaves `async fn` tests cooperatively
    // rather than running them one at a time, and `window.ethereum` is a
    // process-wide global, so two interleaved tests installing different
    // mocks would otherwise stomp on each other. See test_support.rs.

    #[wasm_bindgen_test]
    async fn detect_returns_none_without_a_provider() {
        let _guard = lock_global_mocks().await;
        remove_mock_ethereum();
        assert!(detect().is_none());
    }

    #[wasm_bindgen_test]
    async fn detect_returns_some_with_a_provider() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum("return Promise.resolve([]);", true);
        assert!(detect().is_some());
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn is_meta_mask_reflects_the_provider_flag() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum("return Promise.resolve([]);", true);
        assert!(detect().unwrap().is_meta_mask());

        install_mock_ethereum("return Promise.resolve([]);", false);
        assert!(!detect().unwrap().is_meta_mask());
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn request_accounts_returns_addresses() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(
            r#"if (method === "eth_requestAccounts") { return Promise.resolve(["0xabc123"]); }
               return Promise.reject(new Error("unexpected method: " + method));"#,
            true,
        );
        let wallet = detect().unwrap();
        let accounts = wallet.request_accounts().await.unwrap();
        assert_eq!(accounts, vec!["0xabc123".to_string()]);
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn request_accounts_surfaces_wallet_rejection() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(
            r#"return Promise.reject(new Error("user rejected"));"#,
            true,
        );
        let wallet = detect().unwrap();
        let err = wallet.request_accounts().await.unwrap_err();
        assert!(err.to_string().contains("wallet rejected connection"));
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn accounts_returns_already_authorised_addresses() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(
            r#"if (method === "eth_accounts") { return Promise.resolve(["0xdef456", "0x111"]); }
               return Promise.reject(new Error("unexpected"));"#,
            true,
        );
        let wallet = detect().unwrap();
        let accounts = wallet.accounts().await.unwrap();
        assert_eq!(accounts, vec!["0xdef456".to_string(), "0x111".to_string()]);
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn accounts_returns_empty_when_none_authorised() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(r#"return Promise.resolve([]);"#, true);
        let wallet = detect().unwrap();
        let accounts = wallet.accounts().await.unwrap();
        assert!(accounts.is_empty());
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn chain_id_returns_hex_string() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(r#"return Promise.resolve("0x7a69");"#, true);
        let wallet = detect().unwrap();
        assert_eq!(wallet.chain_id().await.unwrap(), "0x7a69");
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn eth_call_sends_to_and_data_and_decodes_hex_response() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(
            r#"if (method === "eth_call") {
                 if (params[0].to !== "0xCONTRACT" || params[0].data !== "0xdeadbeef") {
                   return Promise.reject(new Error("bad params: " + JSON.stringify(params)));
                 }
                 return Promise.resolve("0x0102030a");
               }
               return Promise.reject(new Error("unexpected method"));"#,
            true,
        );
        let wallet = detect().unwrap();
        let resp = wallet
            .eth_call("0xCONTRACT", &[0xde, 0xad, 0xbe, 0xef])
            .await
            .unwrap();
        assert_eq!(resp, vec![0x01, 0x02, 0x03, 0x0a]);
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn eth_call_rejects_non_hex_response() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(r#"return Promise.resolve("not-hex");"#, true);
        let wallet = detect().unwrap();
        let err = wallet.eth_call("0xCONTRACT", &[0x01]).await.unwrap_err();
        assert!(err.to_string().contains("invalid hex"));
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn eth_call_rejects_non_string_response() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(r#"return Promise.resolve(42);"#, true);
        let wallet = detect().unwrap();
        let err = wallet.eth_call("0xCONTRACT", &[0x01]).await.unwrap_err();
        assert!(err.to_string().contains("non-string"));
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn send_transaction_sends_from_to_data_and_returns_hash() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(
            r#"if (method === "eth_sendTransaction") {
                 const tx = params[0];
                 if (tx.from !== "0xFROM" || tx.to !== "0xTO" || tx.data !== "0xcafe") {
                   return Promise.reject(new Error("bad tx: " + JSON.stringify(tx)));
                 }
                 return Promise.resolve("0xTXHASH");
               }
               return Promise.reject(new Error("unexpected method"));"#,
            true,
        );
        let wallet = detect().unwrap();
        let hash = wallet
            .send_transaction("0xFROM", "0xTO", &[0xca, 0xfe])
            .await
            .unwrap();
        assert_eq!(hash, "0xTXHASH");
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn send_transaction_surfaces_wallet_rejection() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(
            r#"return Promise.reject(new Error("user denied transaction signature"));"#,
            true,
        );
        let wallet = detect().unwrap();
        let err = wallet
            .send_transaction("0xFROM", "0xTO", &[0x01])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("wallet rejected transaction"));
        remove_mock_ethereum();
    }

    #[wasm_bindgen_test]
    async fn on_accounts_changed_does_not_panic_without_a_real_listener_api() {
        let _guard = lock_global_mocks().await;
        install_mock_ethereum(r#"return Promise.resolve([]);"#, true);
        let wallet = detect().unwrap();
        let handle = wallet.on_accounts_changed(|_accounts| {});
        handle.leak();
        remove_mock_ethereum();
    }
}
