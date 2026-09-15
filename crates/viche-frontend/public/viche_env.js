// viche_env.js — per-deployment runtime configuration.
//
// Everything here is OPTIONAL and empty by default. It exists so a single
// built bundle can serve several environments without a rebuild: edit this one
// file inside the deployed `dist/` and reload. See docs/deployment.md §4.3.
//
// Why a file rather than an inline <script>: the app ships
// `script-src 'self' 'wasm-unsafe-eval'` with no 'unsafe-inline', so an inline
// <script> pasted into index.html is refused by the browser and the overrides
// silently never apply. This file is same-origin, so it is allowed — and it
// keeps the override point in one obvious, greppable place.
//
// `src/config.rs` reads these off `window`, falling back to the compile-time
// VICHE_* env vars and then to same-origin `/api`.
//
// IMPORTANT: pointing __VICHE_RELAYER_URL__ at a *different origin* also
// requires that origin in the CSP's `connect-src`, which is not something this
// file can change (the policy is already parsed by then). Either rebuild with
// VICHE_CSP_CONNECT_SRC set, or add the origin to the reverse proxy's
// Content-Security-Policy header — see docs/deployment.md §4.5.

// window.__VICHE_RELAYER_URL__ = "https://relayer.example.com";
// window.__VICHE_VOTING_MANAGER_ADDRESS__ = "0x...";
// window.__VICHE_CHAIN_ID__ = "0xaa36a7"; // 11155111 (Sepolia)
