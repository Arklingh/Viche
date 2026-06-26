//! Small helpers for converting between Rust [`U256`] and JS bigints.
//!
//! JS exposes `bigint` as a primitive; `wasm-bindgen` maps it to `js_sys::BigInt`.
//! We convert via decimal strings — the only lossless, locale-independent channel
//! between a Rust 256-bit integer and a JS bigint.

use alloy_primitives::U256;
use js_sys::JsString;
use viche_core::field::MODULUS_DEC;
use viche_core::poseidon::PoseidonError;
use wasm_bindgen::JsCast;

/// Read a global property off `window` (or `globalThis`), if present.
pub fn global_get(key: &str) -> Option<wasm_bindgen::JsValue> {
    let global = js_sys::global();
    let prop = wasm_bindgen::JsValue::from_str(key);
    let v = js_sys::Reflect::get(&global, &prop).ok()?;
    if v.is_undefined() || v.is_null() {
        None
    } else {
        Some(v)
    }
}

/// Convert a Rust [`U256`] into a JS `bigint` string value.
///
/// circomlibjs's `F` arithmetic operates on JS bigint objects. We convert
/// by serialising the U256 as a decimal string, which circomlibjs's
/// `F.e()` / `F.toObject()` roundtrips through natively.
pub fn u256_to_js_bigint(
    v: &U256,
) -> Result<wasm_bindgen::JsValue, viche_core::poseidon::PoseidonError> {
    // circomlibjs expects decimal string inputs for field elements.
    Ok(wasm_bindgen::JsValue::from_str(&v.to_string()))
}

/// Convert a JS `bigint` (or a string/number that can be turned into one)
/// into a Rust [`U256`].
pub fn js_bigint_to_u256(v: &wasm_bindgen::JsValue) -> Result<U256, PoseidonError> {
    // circomlibjs's F.toObject returns a JS bigint.
    let dec_string: String = if let Ok(b) = v.clone().dyn_into::<js_sys::BigInt>() {
        // bigint.toString(10)
        let s: JsString = b
            .to_string(10)
            .map_err(|e| PoseidonError::Bridge(format!("bigint.toString failed: {:?}", e)))?
            .into();
        s.into()
    } else if let Ok(s) = v.clone().dyn_into::<JsString>() {
        s.into()
    } else {
        return Err(PoseidonError::Bridge(format!(
            "expected bigint/string, got {:?}",
            v.js_typeof()
        )));
    };

    U256::from_str_radix(dec_string.trim(), 10)
        .map_err(|e| PoseidonError::Bridge(format!("U256 parse failed: {} ({})", e, dec_string)))
}
