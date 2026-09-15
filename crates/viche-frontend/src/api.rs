//! HTTP client for the relayer and chain reads.
//!
//! All network calls go through [`ApiClient`], which holds the relayer base
//! URL and centralises JSON (de)serialisation and error handling. Uses
//! `gloo-net` (built on `fetch`), which works in the browser and avoids the
//! `tokio` dependency the rest of the WASM bundle can't link.

use alloy_primitives::U256;
use anyhow::{anyhow, Result};
use gloo_net::http::{Request, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use viche_core::wire::{
    CommitmentListResponse, PollData, PollListResponse, PublishRegistrationRequest,
    PublishRegistrationResponse, RegisterRequest, RegisterResponse, TallyResponse, VoteRequest,
    VoteResponse,
};

// =========================================================================
// Registration review wire types
// =========================================================================
//
// The relayer keeps its approve/reject types private, so these are local
// mirrors of that contract rather than shared `viche-core::wire` types.
// Two consequences worth stating plainly:
//
// * They are **not** compiler-checked against the relayer. A field rename on
//   either side shows up as a runtime 400, not a build failure. The tests at
//   the bottom of this file pin the exact JSON so a drift at least fails
//   loudly here.
// * `U256` is used bare, exactly as `viche_core::wire::CommitmentListResponse`
//   does. That matters: the commitments being approved come straight out of
//   `fetch_pending_registrations`, which decodes that very type, so using the
//   same representation makes the round trip self-consistent by construction.
//   Note that alloy serialises `U256` as a **hex** string (`"0x4d2"`), not
//   decimal — see `u256_serialises_as_hex_not_decimal` below.

/// Request body for `POST /api/admin/registrations/approve` and
/// `POST /api/admin/registrations/reject`.
///
/// Either `commitments` is non-empty **or** `all` is true; sending neither is
/// a 400. Both fields are `#[serde(default)]` on the relayer side, and are
/// mirrored that way here so a payload omitting one still decodes.
///
/// `all` is ignored by the reject route.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRegistrationsRequest {
    /// The exact commitments to act on.
    ///
    /// Preferred over `all` by this client: it names the batch the admin
    /// actually looked at, so a registration that arrived between the refresh
    /// and the click is not swept in unreviewed.
    #[serde(default)]
    pub commitments: Vec<U256>,
    /// Act on the entire pending batch instead of an explicit list.
    ///
    /// Per the relayer's own docs this is "an explicit act on an explicit
    /// batch — 'I have reviewed this list' — not a way to turn the review
    /// step off". Supported here for contract completeness; the admin UI
    /// deliberately sends an explicit list instead.
    #[serde(default)]
    pub all: bool,
}

/// Response for the approve / reject routes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRegistrationsResponse {
    /// How many pending entries actually changed state.
    pub affected: usize,
    /// Commitments the relayer did not recognise.
    ///
    /// The relayer omits this field entirely when empty
    /// (`skip_serializing_if`), hence `#[serde(default)]` — without it every
    /// successful call would fail to decode. Surfacing it is the point: a
    /// mistyped or stale list is visible instead of silently half-applied.
    #[serde(default)]
    pub unknown: Vec<U256>,
    /// Pending entries remaining after the call.
    pub total_pending: usize,
}

/// Why `POST /api/admin/registrations/snapshot` failed.
///
/// Split out because one failure mode is routine and fixable by the admin,
/// and the rest are not. With `REGISTRATION_REQUIRE_APPROVAL=true` the
/// relayer refuses to drain a non-empty pending batch in which nothing is
/// approved — returning an error rather than an empty list, because an empty
/// whitelist would produce a poll nobody can vote in. That deserves
/// "approve the pending registrations first", not a raw HTTP error.
#[derive(Debug)]
pub enum SnapshotFailure {
    /// The batch is non-empty but nothing in it is approved yet.
    NothingApproved(String),
    /// Transport error, auth failure, relayer down, anything else.
    Other(anyhow::Error),
}

impl std::fmt::Display for SnapshotFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotFailure::NothingApproved(detail) => f.write_str(detail),
            SnapshotFailure::Other(e) => write!(f, "{e}"),
        }
    }
}

/// Classify a failed snapshot response body.
///
/// Matched on a keyword rather than an exact string: the relayer's wording
/// ("no approved registrations", "nothing approved", "requires approval") is
/// not part of any contract and would be brittle to pin. A false negative
/// just means the admin sees the raw error, which is the old behaviour — so
/// this can only improve the message, never hide one.
fn is_nothing_approved(status: u16, body: &str) -> bool {
    (400..500).contains(&status) && body.to_lowercase().contains("approv")
}

/// Thin wrapper around the relayer's HTTP API.
#[derive(Clone)]
pub struct ApiClient {
    /// Base URL for the relayer (e.g. `https://relayer.example.com` or `""`
    /// for same-origin in dev via the Trunk proxy).
    base: String,
}

impl ApiClient {
    /// Construct a client targeting the given relayer base URL.
    ///
    /// Pass an empty string to use same-origin paths (the Trunk dev proxy or a
    /// production reverse proxy).
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
        }
    }

    /// `GET /api/polls` — list every poll.
    pub async fn fetch_polls(&self) -> Result<Vec<PollData>> {
        let url = format!("{}/api/polls", self.base);
        let resp = self.get(&url).await?;
        let body: PollListResponse = decode_json(resp).await?;
        Ok(body.polls)
    }

    /// `GET /api/polls/:id` — fetch one poll.
    pub async fn fetch_poll(&self, poll_id: &str) -> Result<PollData> {
        let url = format!("{}/api/polls/{}", self.base, poll_id);
        let resp = self.get(&url).await?;
        decode_json(resp).await
    }

    /// `GET /api/polls/:id/tally` — fetch a poll's tallies.
    pub async fn fetch_tally(&self, poll_id: &str) -> Result<TallyResponse> {
        let url = format!("{}/api/polls/{}/tally", self.base, poll_id);
        let resp = self.get(&url).await?;
        decode_json(resp).await
    }

    /// `POST /api/vote` — submit a vote for broadcasting.
    pub async fn submit_vote(&self, req: &VoteRequest) -> Result<VoteResponse> {
        let url = format!("{}/api/vote", self.base);
        let resp = Request::post(&url)
            .header("Content-Type", "application/json")
            .json(req)
            .map_err(|e| anyhow!("failed to serialise vote request: {:?}", e))?
            .send()
            .await
            .map_err(|e| anyhow!("submit_vote request failed: {:?}", e))?;

        if resp.ok() {
            decode_json(resp).await
        } else {
            let status = resp.status();
            let text = resp
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".into());
            Err(anyhow!("relayer rejected vote ({}): {}", status, text))
        }
    }

    /// `GET /api/polls/:id/registrations` — the commitment list a poll's
    /// whitelist was built from, so a voter's browser can rebuild the tree.
    pub async fn fetch_poll_registrations(&self, poll_id: &str) -> Result<Vec<alloy_primitives::U256>> {
        let url = format!("{}/api/polls/{}/registrations", self.base, poll_id);
        let resp = self.get(&url).await?;
        let body: CommitmentListResponse = decode_json(resp).await?;
        Ok(body.commitments)
    }

    /// `POST /api/register` — submit an identity commitment ahead of the
    /// next poll. Public; no admin key required.
    pub async fn register(&self, req: &RegisterRequest) -> Result<RegisterResponse> {
        let url = format!("{}/api/register", self.base);
        let resp = Request::post(&url)
            .header("Content-Type", "application/json")
            .json(req)
            .map_err(|e| anyhow!("failed to serialise register request: {:?}", e))?
            .send()
            .await
            .map_err(|e| anyhow!("register request failed: {:?}", e))?;
        Self::decode_or_error(resp, "POST /api/register").await
    }

    /// `GET /api/admin/registrations/pending` — owner-only.
    pub async fn fetch_pending_registrations(
        &self,
        admin_api_key: &str,
    ) -> Result<Vec<alloy_primitives::U256>> {
        let url = format!("{}/api/admin/registrations/pending", self.base);
        let resp = Request::get(&url)
            .header("Authorization", &format!("Bearer {}", admin_api_key))
            .send()
            .await
            .map_err(|e| anyhow!("GET {} failed: {:?}", url, e))?;
        let body: CommitmentListResponse =
            Self::decode_or_error(resp, "GET /api/admin/registrations/pending").await?;
        Ok(body.commitments)
    }

    /// `POST /api/admin/registrations/approve` — owner-only. Marks entries in
    /// the pending batch as reviewed and eligible for the next snapshot.
    ///
    /// Deliberately *not* called as part of the snapshot/build flow. The
    /// approval gate exists because `POST /api/register` is public: without
    /// review, an attacker floods the pending list and a blind snapshot hands
    /// them the electorate. Folding this into the build button would restore
    /// that hole while looking like a bug fix.
    pub async fn approve_registrations(
        &self,
        admin_api_key: &str,
        req: &ReviewRegistrationsRequest,
    ) -> Result<ReviewRegistrationsResponse> {
        self.post_admin_review("approve", admin_api_key, req).await
    }

    /// `POST /api/admin/registrations/reject` — owner-only. Drops entries
    /// from the pending batch.
    ///
    /// The other half of a real review step: without it a rejected Sybil
    /// batch lingers forever and every later review has to re-scan it.
    /// `ReviewRegistrationsRequest::all` is ignored by this route.
    pub async fn reject_registrations(
        &self,
        admin_api_key: &str,
        req: &ReviewRegistrationsRequest,
    ) -> Result<ReviewRegistrationsResponse> {
        self.post_admin_review("reject", admin_api_key, req).await
    }

    /// Shared body of [`Self::approve_registrations`] / [`Self::reject_registrations`],
    /// which differ only in the path segment.
    async fn post_admin_review(
        &self,
        action: &str,
        admin_api_key: &str,
        req: &ReviewRegistrationsRequest,
    ) -> Result<ReviewRegistrationsResponse> {
        let url = format!("{}/api/admin/registrations/{}", self.base, action);
        let resp = Request::post(&url)
            .header("Authorization", &format!("Bearer {}", admin_api_key))
            .header("Content-Type", "application/json")
            .json(req)
            .map_err(|e| anyhow!("failed to serialise {} request: {:?}", action, e))?
            .send()
            .await
            .map_err(|e| anyhow!("POST {} failed: {:?}", url, e))?;
        Self::decode_or_error(resp, &format!("POST /api/admin/registrations/{action}")).await
    }

    /// `POST /api/admin/registrations/snapshot` — owner-only. Locks in the
    /// current *approved* batch and returns it.
    ///
    /// Returns [`SnapshotFailure::NothingApproved`] when the relayer refuses
    /// because the pending batch has no approved entries, so the caller can
    /// point the admin at the approve step instead of showing an HTTP error.
    pub async fn snapshot_registrations(
        &self,
        admin_api_key: &str,
    ) -> std::result::Result<Vec<U256>, SnapshotFailure> {
        let url = format!("{}/api/admin/registrations/snapshot", self.base);
        let resp = Request::post(&url)
            .header("Authorization", &format!("Bearer {}", admin_api_key))
            .send()
            .await
            .map_err(|e| SnapshotFailure::Other(anyhow!("POST {} failed: {:?}", url, e)))?;

        if resp.ok() {
            let body: CommitmentListResponse = decode_json(resp)
                .await
                .map_err(SnapshotFailure::Other)?;
            return Ok(body.commitments);
        }

        let status = resp.status();
        let text = resp
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable body>".into());
        if is_nothing_approved(status, &text) {
            Err(SnapshotFailure::NothingApproved(text))
        } else {
            Err(SnapshotFailure::Other(anyhow!(
                "POST /api/admin/registrations/snapshot returned {}: {}",
                status,
                text
            )))
        }
    }

    /// `POST /api/admin/registrations/publish` — owner-only. Stores the
    /// snapshot under the given (client-computed) Merkle root.
    pub async fn publish_registration(
        &self,
        admin_api_key: &str,
        req: &PublishRegistrationRequest,
    ) -> Result<PublishRegistrationResponse> {
        let url = format!("{}/api/admin/registrations/publish", self.base);
        let resp = Request::post(&url)
            .header("Authorization", &format!("Bearer {}", admin_api_key))
            .header("Content-Type", "application/json")
            .json(req)
            .map_err(|e| anyhow!("failed to serialise publish request: {:?}", e))?
            .send()
            .await
            .map_err(|e| anyhow!("POST {} failed: {:?}", url, e))?;
        Self::decode_or_error(resp, "POST /api/admin/registrations/publish").await
    }

    // ----- internals -------------------------------------------------------

    async fn get(&self, url: &str) -> Result<Response> {
        let resp = Request::get(url)
            .send()
            .await
            .map_err(|e| anyhow!("GET {} failed: {:?}", url, e))?;
        if resp.ok() {
            Ok(resp)
        } else {
            let status = resp.status();
            let text = resp
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".into());
            Err(anyhow!("GET {} returned {}: {}", url, status, text))
        }
    }

    /// Decode a JSON body on success, or surface the relayer's error text
    /// (including its status code) on failure. Shared by every non-`GET`
    /// call above, which don't go through [`Self::get`]'s `GET`-specific
    /// error message.
    async fn decode_or_error<T: DeserializeOwned>(resp: Response, what: &str) -> Result<T> {
        if resp.ok() {
            decode_json(resp).await
        } else {
            let status = resp.status();
            let text = resp
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".into());
            Err(anyhow!("{} returned {}: {}", what, status, text))
        }
    }
}

/// Decode a JSON body into `T`, surfacing parse errors with the raw text.
async fn decode_json<T: DeserializeOwned>(resp: Response) -> Result<T> {
    resp.json()
        .await
        .map_err(|e| anyhow!("failed to decode JSON response: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are contract tests against a service this crate cannot see at
    // compile time. They exist so that a mismatch with the relayer surfaces
    // as a failing unit test with a readable diff, rather than as a 400 in
    // an admin's browser mid-poll-setup.

    #[test]
    fn u256_serialises_as_hex_not_decimal() {
        // Documents the actual alloy representation. If the relayer's
        // approve types use bare `U256` too (as the shared wire types do),
        // both sides agree automatically. If this ever needs to be decimal,
        // this test is where that decision gets recorded.
        let json = serde_json::to_string(&vec![U256::from(1234u64)]).unwrap();
        assert_eq!(json, r#"["0x4d2"]"#);
    }

    #[test]
    fn review_request_serialises_both_fields() {
        let req = ReviewRegistrationsRequest {
            commitments: vec![U256::from(1u64), U256::from(2u64)],
            all: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"commitments":["0x1","0x2"],"all":false}"#);
    }

    #[test]
    fn review_request_supports_the_all_form() {
        let req = ReviewRegistrationsRequest {
            commitments: vec![],
            all: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"commitments":[],"all":true}"#);
    }

    #[test]
    fn review_request_decodes_with_either_field_omitted() {
        // Both fields are `#[serde(default)]` on the relayer side.
        let only_all: ReviewRegistrationsRequest =
            serde_json::from_str(r#"{"all":true}"#).unwrap();
        assert!(only_all.all);
        assert!(only_all.commitments.is_empty());

        let only_list: ReviewRegistrationsRequest =
            serde_json::from_str(r#"{"commitments":["0x7"]}"#).unwrap();
        assert!(!only_list.all);
        assert_eq!(only_list.commitments, vec![U256::from(7u64)]);
    }

    #[test]
    fn review_response_decodes_when_unknown_is_omitted() {
        // The relayer omits `unknown` entirely when empty
        // (`skip_serializing_if`). Without `#[serde(default)]` this — the
        // *common* success case — would fail to decode.
        let resp: ReviewRegistrationsResponse =
            serde_json::from_str(r#"{"affected":3,"total_pending":5}"#).unwrap();
        assert_eq!(resp.affected, 3);
        assert_eq!(resp.total_pending, 5);
        assert!(resp.unknown.is_empty());
    }

    #[test]
    fn review_response_decodes_unknown_when_present() {
        let resp: ReviewRegistrationsResponse =
            serde_json::from_str(r#"{"affected":1,"unknown":["0x9"],"total_pending":2}"#)
                .unwrap();
        assert_eq!(resp.affected, 1);
        assert_eq!(resp.unknown, vec![U256::from(9u64)]);
        assert_eq!(resp.total_pending, 2);
    }

    // ---- snapshot failure classification ---------------------------------

    #[test]
    fn nothing_approved_is_recognised_across_plausible_wordings() {
        // The exact text is not a contract, so match loosely on purpose.
        for body in [
            "no approved registrations to snapshot",
            "Nothing approved in the pending batch",
            "snapshot requires approval",
            "NO APPROVED ENTRIES",
        ] {
            assert!(is_nothing_approved(409, body), "missed: {body}");
        }
    }

    #[test]
    fn unrelated_failures_are_not_misread_as_nothing_approved() {
        assert!(!is_nothing_approved(401, "unauthorized"));
        assert!(!is_nothing_approved(400, "malformed body"));
        // A 5xx is never the approval gate, even if the word appears.
        assert!(!is_nothing_approved(500, "approval subsystem panicked"));
    }

    #[test]
    fn snapshot_failure_displays_the_relayer_detail() {
        let f = SnapshotFailure::NothingApproved("nothing approved".into());
        assert_eq!(f.to_string(), "nothing approved");
        let f = SnapshotFailure::Other(anyhow!("relayer down"));
        assert_eq!(f.to_string(), "relayer down");
    }
}
