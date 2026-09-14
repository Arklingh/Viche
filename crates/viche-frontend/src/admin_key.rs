//! The relayer's `ADMIN_API_KEY`: held in memory for the session, never
//! written to web storage.
//!
//! # What this credential is
//!
//! It is *not* the wallet-based admin gate. `is_admin` compares the connected
//! account against the on-chain `VotingManager.owner` and only decides whether
//! to render the admin page; the chain enforces `onlyOwner` regardless. This
//! key is the bearer token for the relayer's `/api/admin/registrations/*`
//! routes, which snapshot the pending commitment list and publish a whitelist
//! root. Whoever holds it can decide who is in the next poll's Merkle tree.
//!
//! # Why it is no longer persisted
//!
//! It used to live in `localStorage` under a fixed key. `localStorage` is
//! readable by any JavaScript running on the origin, so a single XSS anywhere
//! in the app — an injected `<script>`, a compromised CDN dependency, a
//! malicious browser extension with host access — could read the key out and
//! keep it forever. With the key in hand an attacker can snapshot
//! registrations and publish a whitelist root of their own choosing, which is
//! full control over who may vote.
//!
//! Three options were on the table:
//!
//! | option | XSS exposure | admin UX |
//! |---|---|---|
//! | `localStorage` (before) | permanent; survives restarts | type once, ever |
//! | `sessionStorage` | any XSS while the tab is open | type once per tab |
//! | in-memory only (now) | only script running *during* the session, and only if it reaches the signal | type once per page load |
//!
//! `sessionStorage` is a real improvement over `localStorage` but it is still
//! a named, enumerable slot that `Object.keys(sessionStorage)` hands to an
//! attacker with no knowledge of the app. The in-memory option removes the
//! slot entirely: the key exists only inside a Leptos signal in the WASM
//! heap, with no stable global path to it.
//!
//! The UX cost is small and lands on the right person. The admin flow is
//! rare (build a whitelist, create a poll, close a poll) and already involves
//! signing wallet transactions, so re-pasting a key once per page load is
//! noise next to that — and unlike a voter losing a secret, a re-paste is
//! recoverable. The key lives in [`crate::state::AppSignals`], which is
//! created once in `App`, so it survives navigating between the admin page
//! and the poll list; only a reload or tab close clears it.
//!
//! # Handling rules
//!
//! * Sent only as an `Authorization: Bearer` header, only to the relayer's
//!   `/api/admin/*` endpoints (see [`crate::api::ApiClient`]).
//! * Never a URL path segment or query parameter — those end up in server
//!   logs, `Referer` headers, and browser history.
//! * Never logged, never in an error message, never in a panic payload. Use
//!   [`fingerprint`] if a message has to refer to a specific key.
//! * Cleared explicitly by the admin, and automatically when the wallet
//!   disconnects or switches accounts.

use crate::storage::{self, WebStorage};

/// The `localStorage` key older builds persisted the admin API key under.
///
/// Kept only so [`purge_persisted_admin_api_key`] can delete it.
pub const LEGACY_ADMIN_KEY_STORAGE_KEY: &str = "viche:admin_api_key";

/// Delete any admin key an older build left in web storage.
///
/// Returns `true` if something was actually there, so the UI can tell the
/// admin to **rotate the key**: it sat in `localStorage` for however long,
/// which is exactly the exposure this change removes. Deleting it now does
/// not un-expose it.
///
/// Checks `sessionStorage` too, so an intermediate build that moved the key
/// there is cleaned up as well.
pub fn purge_persisted_admin_api_key() -> bool {
    let mut found = false;
    for area in [WebStorage::Local, WebStorage::Session] {
        // A read failure means storage is unreachable, which also means there
        // is nothing stored to leak — the one place ignoring the error is
        // right.
        if matches!(
            storage::get(area, LEGACY_ADMIN_KEY_STORAGE_KEY),
            Ok(Some(_))
        ) {
            found = true;
        }
        storage::remove_best_effort(area, LEGACY_ADMIN_KEY_STORAGE_KEY);
    }
    found
}

/// Whether a pasted string is worth sending to the relayer at all.
///
/// Purely a "don't fire an obviously-doomed request" check; the relayer is
/// the authority on whether a key is valid.
pub fn is_usable(key: &str) -> bool {
    !key.trim().is_empty()
}

/// A short, non-reversible label for a key, safe to show on screen.
///
/// Used so the admin can confirm *which* key is loaded without the full
/// secret ever being rendered, selectable, or screenshot-able. Deliberately
/// only the last four characters: enough to distinguish two keys the admin
/// has in a password manager, useless to anyone who doesn't already have it.
pub fn fingerprint(key: &str) -> String {
    let key = key.trim();
    let len = key.chars().count();
    if len <= 4 {
        return "****".to_string();
    }
    let tail: String = key.chars().skip(len - 4).collect();
    format!("****{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_usable_rejects_blank_input() {
        assert!(!is_usable(""));
        assert!(!is_usable("   \n"));
        assert!(is_usable("s3cret"));
    }

    #[test]
    fn fingerprint_never_reveals_more_than_four_characters() {
        assert_eq!(fingerprint("abcdefghij"), "****ghij");
        // Short keys reveal nothing at all rather than most of themselves.
        assert_eq!(fingerprint("abcd"), "****");
        assert_eq!(fingerprint("ab"), "****");
        assert_eq!(fingerprint(""), "****");
    }

    #[test]
    fn fingerprint_ignores_surrounding_whitespace() {
        assert_eq!(fingerprint("  abcdefghij  "), "****ghij");
    }

    #[test]
    fn fingerprint_is_char_safe_for_multibyte_keys() {
        // Slicing by byte index would panic here.
        assert_eq!(fingerprint("aaaa\u{00e9}\u{00e9}\u{00e9}\u{00e9}"), "****\u{00e9}\u{00e9}\u{00e9}\u{00e9}");
    }
}

#[cfg(test)]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::*;

    // `run_in_browser` is declared once, crate-wide, in `test_support`.

    #[wasm_bindgen_test]
    fn purge_deletes_a_legacy_local_storage_key_and_reports_it() {
        storage::set(
            WebStorage::Local,
            LEGACY_ADMIN_KEY_STORAGE_KEY,
            "leaked-key",
        )
        .unwrap();

        assert!(purge_persisted_admin_api_key(), "should report the find");
        assert_eq!(
            storage::get(WebStorage::Local, LEGACY_ADMIN_KEY_STORAGE_KEY).unwrap(),
            None
        );
        // Idempotent, and quiet when there was nothing to clean up.
        assert!(!purge_persisted_admin_api_key());
    }

    #[wasm_bindgen_test]
    fn purge_also_clears_session_storage() {
        storage::set(
            WebStorage::Session,
            LEGACY_ADMIN_KEY_STORAGE_KEY,
            "leaked-key",
        )
        .unwrap();

        assert!(purge_persisted_admin_api_key());
        assert_eq!(
            storage::get(WebStorage::Session, LEGACY_ADMIN_KEY_STORAGE_KEY).unwrap(),
            None
        );
    }

    #[wasm_bindgen_test]
    fn nothing_in_this_module_writes_the_key_anywhere() {
        // Regression guard for the whole point of the module: after using the
        // in-memory helpers, no storage slot holds the key.
        let key = "super-secret-admin-key";
        assert!(is_usable(key));
        let _ = fingerprint(key);

        for area in [WebStorage::Local, WebStorage::Session] {
            assert_eq!(
                storage::get(area, LEGACY_ADMIN_KEY_STORAGE_KEY).unwrap(),
                None
            );
        }
    }
}
