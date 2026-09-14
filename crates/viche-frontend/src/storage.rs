//! Web-storage access that **never** swallows a failure.
//!
//! The previous helpers in `actions.rs` returned `Option<String>` / `Option<()>`
//! and every call site did `let _ = ...`. That is fine for a UI preference and
//! catastrophic for a voter's secret: in a private-browsing window, at quota,
//! or with site data blocked, `setItem` throws, the `Option` collapses to
//! `None`, and the voter registers a commitment whose pre-image is gone
//! forever. The whole point of this module is that a write failure is a typed,
//! *reportable* value that the caller is forced to look at.
//!
//! Three failure modes matter in practice, and they need different advice:
//!
//! * **Unavailable** — `window.localStorage` itself throws on access. Firefox
//!   and Safari do this when "block all cookies"/"block site data" is on, and
//!   Chrome does it inside a sandboxed iframe. Nothing can be stored at all.
//! * **QuotaExceeded** — the origin is at its storage budget. Common in
//!   long-lived private windows, where the quota is a fraction of the normal
//!   one.
//! * **Rejected** — anything else the DOM threw, surfaced verbatim so a bug
//!   report has something to go on.
//!
//! [`set`] also reads the value back after writing it. Storage that accepts a
//! write and drops it is rare but not unheard of (some privacy extensions
//! stub `setItem` into a no-op), and read-back is far cheaper than a lost
//! ballot.

use std::fmt;

/// Which of the two `Window` storage areas to talk to.
///
/// [`Session`](WebStorage::Session) is scoped to the tab and cleared when it
/// closes; it is the right home for short-lived credentials. [`Local`](WebStorage::Local)
/// survives restarts and is the right home for a cache the user expects to
/// outlive a reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebStorage {
    /// `window.localStorage` — persists across sessions.
    Local,
    /// `window.sessionStorage` — cleared when the tab closes.
    Session,
}

impl WebStorage {
    /// Human name used in error messages.
    fn name(self) -> &'static str {
        match self {
            WebStorage::Local => "localStorage",
            WebStorage::Session => "sessionStorage",
        }
    }

    /// Resolve the underlying `web_sys::Storage`, or say why we can't.
    fn resolve(self) -> Result<web_sys::Storage, StorageError> {
        let win = web_sys::window().ok_or(StorageError::Unavailable {
            area: self.name(),
            detail: "no browser window context".to_string(),
        })?;
        let slot = match self {
            WebStorage::Local => win.local_storage(),
            WebStorage::Session => win.session_storage(),
        };
        match slot {
            // Accessing the property itself throws when site data is blocked.
            Err(e) => Err(StorageError::Unavailable {
                area: self.name(),
                detail: js_error_message(&e),
            }),
            Ok(None) => Err(StorageError::Unavailable {
                area: self.name(),
                detail: "the browser reported no storage area for this origin".to_string(),
            }),
            Ok(Some(s)) => Ok(s),
        }
    }
}

/// Why a storage operation could not be completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// The storage area cannot be reached at all (blocked site data, sandboxed
    /// frame, no `window`).
    Unavailable {
        /// `"localStorage"` / `"sessionStorage"`.
        area: &'static str,
        /// What the browser said.
        detail: String,
    },
    /// The origin is out of storage budget.
    QuotaExceeded {
        /// `"localStorage"` / `"sessionStorage"`.
        area: &'static str,
    },
    /// Some other DOM exception.
    Rejected {
        /// `"localStorage"` / `"sessionStorage"`.
        area: &'static str,
        /// What the browser said.
        detail: String,
    },
    /// The write appeared to succeed but reading it back returned something
    /// else (or nothing).
    NotPersisted {
        /// `"localStorage"` / `"sessionStorage"`.
        area: &'static str,
    },
}

impl StorageError {
    /// A message written for the person staring at the screen, not for a log.
    ///
    /// Every branch names a concrete thing the user can do, because the
    /// alternative — the old `let _ = ...` — told them nothing at all.
    pub fn user_message(&self) -> String {
        match self {
            StorageError::Unavailable { area, detail } => format!(
                "This browser is blocking site storage, so Viche cannot cache your voting \
                 secret in {area} ({detail}). Allow site data for this page, or leave \
                 private-browsing mode. You can still vote from this tab, but back the \
                 secret up from the \"Voting secret\" panel before you close it."
            ),
            StorageError::QuotaExceeded { area } => format!(
                "This site's {area} is full, so your voting secret could not be saved. \
                 Clear site data for this origin and try again, and back the secret up from \
                 the \"Voting secret\" panel first."
            ),
            StorageError::Rejected { area, detail } => format!(
                "The browser refused to write to {area} ({detail}), so your voting secret \
                 could not be saved. Back it up from the \"Voting secret\" panel before \
                 closing this tab."
            ),
            StorageError::NotPersisted { area } => format!(
                "A write to {area} reported success but did not stick — a privacy extension \
                 is probably stubbing it out. Your voting secret was not saved; back it up \
                 from the \"Voting secret\" panel before closing this tab."
            ),
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.user_message())
    }
}

impl std::error::Error for StorageError {}

/// Read a key, distinguishing "absent" (`Ok(None)`) from "could not read".
pub fn get(area: WebStorage, key: &str) -> Result<Option<String>, StorageError> {
    let storage = area.resolve()?;
    storage.get_item(key).map_err(|e| StorageError::Rejected {
        area: area.name(),
        detail: js_error_message(&e),
    })
}

/// Write a key and verify it stuck.
pub fn set(area: WebStorage, key: &str, value: &str) -> Result<(), StorageError> {
    let storage = area.resolve()?;
    storage.set_item(key, value).map_err(|e| {
        if is_quota_exceeded(&e) {
            StorageError::QuotaExceeded { area: area.name() }
        } else {
            StorageError::Rejected {
                area: area.name(),
                detail: js_error_message(&e),
            }
        }
    })?;

    match storage.get_item(key) {
        Ok(Some(read_back)) if read_back == value => Ok(()),
        _ => Err(StorageError::NotPersisted { area: area.name() }),
    }
}

/// Delete a key. Removing something that isn't there is success.
pub fn remove(area: WebStorage, key: &str) -> Result<(), StorageError> {
    let storage = area.resolve()?;
    storage.remove_item(key).map_err(|e| StorageError::Rejected {
        area: area.name(),
        detail: js_error_message(&e),
    })
}

/// Best-effort delete used only to *clean up* something that should never
/// have been written (see `admin_key::purge_persisted_admin_api_key`).
///
/// This is the one place where ignoring the error is correct: if storage is
/// unreachable there is also nothing stored to leak.
pub fn remove_best_effort(area: WebStorage, key: &str) {
    let _ = remove(area, key);
}

// ---- JsValue error introspection ----------------------------------------

/// Pull a readable message out of whatever the DOM threw.
///
/// `set_item` rejects with a `DOMException`, which has `name` and `message`
/// properties; anything else falls back to the JS string coercion.
fn js_error_message(err: &wasm_bindgen::JsValue) -> String {
    let name = js_string_prop(err, "name");
    let message = js_string_prop(err, "message");
    match (name, message) {
        (Some(n), Some(m)) if !m.is_empty() => format!("{n}: {m}"),
        (Some(n), _) => n,
        (None, Some(m)) => m,
        (None, None) => err
            .as_string()
            .unwrap_or_else(|| "unknown storage error".to_string()),
    }
}

/// Read a string property off a `JsValue`, if it has one.
fn js_string_prop(value: &wasm_bindgen::JsValue, prop: &str) -> Option<String> {
    js_sys::Reflect::get(value, &prop.into())
        .ok()
        .and_then(|v| v.as_string())
}

/// Whether a thrown value is the quota-exceeded `DOMException`.
///
/// Browsers disagree on the name: the modern spelling is
/// `QuotaExceededError`, but Firefox historically used
/// `NS_ERROR_DOM_QUOTA_REACHED` and Safari `QUOTA_EXCEEDED_ERR`. Match on the
/// substring rather than trying to enumerate them.
fn is_quota_exceeded(err: &wasm_bindgen::JsValue) -> bool {
    let name = js_string_prop(err, "name").unwrap_or_default().to_uppercase();
    name.contains("QUOTA")
}

#[cfg(test)]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::*;

    // `run_in_browser` is declared once, crate-wide, in `test_support`.

    #[wasm_bindgen_test]
    fn set_then_get_round_trips_through_local_storage() {
        let key = "viche:test:storage-roundtrip";
        set(WebStorage::Local, key, "hello").unwrap();
        assert_eq!(get(WebStorage::Local, key).unwrap().as_deref(), Some("hello"));
        remove(WebStorage::Local, key).unwrap();
        assert_eq!(get(WebStorage::Local, key).unwrap(), None);
    }

    #[wasm_bindgen_test]
    fn session_storage_is_a_separate_area_from_local_storage() {
        let key = "viche:test:storage-area-split";
        set(WebStorage::Session, key, "session-only").unwrap();
        assert_eq!(get(WebStorage::Local, key).unwrap(), None);
        assert_eq!(
            get(WebStorage::Session, key).unwrap().as_deref(),
            Some("session-only")
        );
        remove(WebStorage::Session, key).unwrap();
    }

    #[wasm_bindgen_test]
    fn missing_key_reads_as_none_not_as_an_error() {
        let result = get(WebStorage::Local, "viche:test:definitely-absent");
        assert_eq!(result.unwrap(), None);
    }

    #[wasm_bindgen_test]
    fn user_message_is_non_empty_and_actionable_for_every_variant() {
        // These strings are the *only* thing a voter sees when storage fails,
        // so assert they at least name the area and say what to do.
        let variants = [
            StorageError::Unavailable {
                area: "localStorage",
                detail: "blocked".into(),
            },
            StorageError::QuotaExceeded {
                area: "localStorage",
            },
            StorageError::Rejected {
                area: "localStorage",
                detail: "SecurityError".into(),
            },
            StorageError::NotPersisted {
                area: "localStorage",
            },
        ];
        for v in variants {
            let msg = v.user_message();
            assert!(msg.contains("localStorage"), "no area named: {msg}");
            assert!(msg.len() > 40, "message too terse to act on: {msg}");
        }
    }

    #[wasm_bindgen_test]
    fn quota_exceeded_is_detected_from_the_dom_exception_name() {
        let fake = js_sys::Object::new();
        js_sys::Reflect::set(&fake, &"name".into(), &"QuotaExceededError".into()).unwrap();
        assert!(is_quota_exceeded(&fake.into()));

        let other = js_sys::Object::new();
        js_sys::Reflect::set(&other, &"name".into(), &"SecurityError".into()).unwrap();
        assert!(!is_quota_exceeded(&other.into()));
    }

    #[wasm_bindgen_test]
    fn js_error_message_prefers_name_and_message() {
        let e = js_sys::Object::new();
        js_sys::Reflect::set(&e, &"name".into(), &"SecurityError".into()).unwrap();
        js_sys::Reflect::set(&e, &"message".into(), &"access denied".into()).unwrap();
        assert_eq!(js_error_message(&e.into()), "SecurityError: access denied");
    }
}
