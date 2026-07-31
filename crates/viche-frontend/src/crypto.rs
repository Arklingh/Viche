//! Poseidon hash via the circomlibjs WASM bridge.
//!
//! This is the browser's implementation of [`viche_core::poseidon::PoseidonProvider`].
//! It calls into `circomlibjs` (loaded as a JS module in `index.html` via a
//! `<script>` tag) through `wasm-bindgen`. Because circomlibjs is the *same*
//! library the circuit was compiled against, the hashes it produces are
//! guaranteed to match — there is no risk of the "Rust port disagrees with
//! circom by one bit" failure mode.
//!
//! ## Loading
//!
//! `circomlibjs` is a CommonJS module that ships a WASM blob. We load it in
//! `index.html`:
//!
//! ```html
//! <script type="module">
//!   import('https://esm.sh/circomlibjs@0.1.7').then(m => {
//!     window.__VICHE_CIRCOMLIB_READY__ = m.buildPoseidon();
//!   });
//! </script>
//! ```
//!
//! Once `window.__VICHE_POSEIDON__` is set, [`CircomlibPoseidon::new`]
//! succeeds. Until then it returns [`PoseidonError::NotReady`].

use anyhow::Result;
use js_sys::Array;
use viche_core::field::is_in_field;
use viche_core::poseidon::{PoseidonError, PoseidonProvider};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::js_helpers::{global_get, js_bigint_to_u256, u256_to_js_bigint};

/// Browser Poseidon provider backed by circomlibjs.
#[derive(Clone)]
pub struct CircomlibPoseidon {
    /// The circomlibjs poseidon object (stored as opaque JsValue).
    inner: wasm_bindgen::JsValue,
    /// The `F` field-arithmetic sub-object, cached.
    f: wasm_bindgen::JsValue,
}

impl CircomlibPoseidon {
    /// Initialise from the global `window.__VICHE_POSEIDON__`.
    ///
    /// Returns `Err(NotReady)` if the circomlibjs module hasn't finished
    /// loading yet. The caller (the app bootstrap) should retry or surface a
    /// "loading crypto engine…" state.
    pub fn new() -> Result<Self, PoseidonError> {
        let raw = global_get("__VICHE_POSEIDON__").ok_or(PoseidonError::NotReady)?;
        if raw.is_undefined() || raw.is_null() {
            return Err(PoseidonError::NotReady);
        }
        let f = js_sys::Reflect::get(&raw, &"F".into())
            .map_err(|_| PoseidonError::Bridge("failed to read .F from poseidon object".into()))?;
        Ok(Self { inner: raw, f })
    }

    /// Poseidon-hash a slice of inputs, returning the reduced field element.
    fn hash(
        &self,
        inputs: &[wasm_bindgen::JsValue],
    ) -> Result<alloy_primitives::U256, PoseidonError> {
        let arr = Array::new();
        for v in inputs {
            arr.push(v);
        }

        // poseidon(inputs) returns a WASM pointer.
        let poseidon_fn = js_sys::Reflect::get(&self.inner, &"poseidon".into())
            .map_err(|_| PoseidonError::Bridge("poseidon is not a function".into()))?;
        let poseidon_args = Array::new();
        poseidon_args.push(arr.as_ref());
        let ptr = js_sys::Reflect::apply(
            &poseidon_fn
                .dyn_into::<js_sys::Function>()
                .map_err(|_| PoseidonError::Bridge("poseidon is not callable".into()))?,
            &self.inner,
            &poseidon_args,
        )
        .map_err(|_| PoseidonError::Bridge("poseidon() call failed".into()))?;

        // F.toObject(ptr) extracts the field element as a bigint.
        let to_object_fn = js_sys::Reflect::get(&self.f, &"toObject".into())
            .map_err(|_| PoseidonError::Bridge("F.toObject is not a function".into()))?;
        let to_object_args = Array::new();
        to_object_args.push(&ptr);
        let bigint_js = js_sys::Reflect::apply(
            &to_object_fn
                .dyn_into::<js_sys::Function>()
                .map_err(|_| PoseidonError::Bridge("F.toObject is not callable".into()))?,
            &self.f,
            &to_object_args,
        )
        .map_err(|_| PoseidonError::Bridge("F.toObject() call failed".into()))?;

        let out = js_bigint_to_u256(&bigint_js)?;
        if !is_in_field(&out) {
            return Err(PoseidonError::OutOfField(out));
        }
        Ok(out)
    }
}

impl PoseidonProvider for CircomlibPoseidon {
    fn hash_1(&self, x: &alloy_primitives::U256) -> Result<alloy_primitives::U256, PoseidonError> {
        if !is_in_field(x) {
            return Err(PoseidonError::OutOfField(*x));
        }
        let js = u256_to_js_bigint(x)?;
        self.hash(&[js])
    }

    fn hash_2(
        &self,
        x: &alloy_primitives::U256,
        y: &alloy_primitives::U256,
    ) -> Result<alloy_primitives::U256, PoseidonError> {
        if !is_in_field(x) {
            return Err(PoseidonError::OutOfField(*x));
        }
        if !is_in_field(y) {
            return Err(PoseidonError::OutOfField(*y));
        }
        let xj = u256_to_js_bigint(x)?;
        let yj = u256_to_js_bigint(y)?;
        self.hash(&[xj, yj])
    }
}
