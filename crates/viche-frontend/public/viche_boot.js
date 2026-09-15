// viche_boot.js — initialise the client-side cryptographic stack.
//
// This used to live as an inline `<script type="module">` in index.html that
// `import()`ed circomlibjs straight off jsdelivr. Two things changed:
//
//   1. circomlibjs and snarkjs are now vendored under `/vendor/` and loaded
//      same-origin (see `public/vendor/VENDOR.md` for why that matters —
//      short version: both libraries handle the voter's `secret` in
//      cleartext, so a CDN compromise is a total break of the anonymity
//      *and* the unforgeability of the whole system).
//
//   2. The code moved out of index.html into this file so the app's
//      Content-Security-Policy can be `script-src 'self' 'wasm-unsafe-eval'`
//      with no `'unsafe-inline'`. Inline scripts are the single biggest
//      reason strict CSPs get watered down; keeping the page free of them is
//      what makes the policy worth having.
//
// Contract with the Rust side (do not change these names without updating
// `src/crypto.rs` / `src/actions.rs`):
//   window.__VICHE_POSEIDON__      the circomlibjs poseidon instance
//   window.poseidon                same object, legacy alias
//   window.__VICHE_CRYPTO_READY__  true once both libs are usable
//   window.__VICHE_CRYPTO_ERROR__  message string if init failed
//   window.__VICHE_CRYPTO_PROMISE__ awaitable init promise

"use strict";

window.__VICHE_CRYPTO_PROMISE__ = (async () => {
    // `circomlibjs` here is the global exposed by the vendored IIFE bundle
    // /vendor/circomlibjs-poseidon.js, not a network import.
    if (!window.circomlibjs || typeof window.circomlibjs.buildPoseidon !== "function") {
        throw new Error(
            "vendored circomlibjs bundle did not expose buildPoseidon " +
            "(is /vendor/circomlibjs-poseidon.js being served?)"
        );
    }

    console.log("[Viche] Compiling Poseidon WebAssembly...");
    const poseidonInstance = await window.circomlibjs.buildPoseidon();

    // Expose poseidon in the namespaces the WASM bridge looks in.
    window.__VICHE_POSEIDON__ = poseidonInstance;
    window.poseidon = poseidonInstance;

    // buildPoseidon() returns a callable with an `.F` field; if a future
    // version returns a plain object instead, fall back to its hash method so
    // `window.poseidon(...)` stays callable.
    if (typeof window.poseidon !== "function") {
        window.poseidon = poseidonInstance.hash || poseidonInstance;
    }

    if (!window.snarkjs || !window.snarkjs.groth16) {
        throw new Error(
            "vendored snarkjs bundle did not expose groth16 " +
            "(is /vendor/snarkjs.min.js being served?)"
        );
    }

    window.__VICHE_CRYPTO_READY__ = true;
    console.log("[Viche] Cryptographic engine initialized (same-origin, vendored).");
})().catch((error) => {
    window.__VICHE_CRYPTO_READY__ = false;
    window.__VICHE_CRYPTO_ERROR__ = String((error && error.message) || error);
    console.error("[Viche] Failed to initialise crypto libraries:", error);
});
