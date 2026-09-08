//! HTTP client for the relayer and chain reads.
//!
//! All network calls go through [`ApiClient`], which holds the relayer base
//! URL and centralises JSON (de)serialisation and error handling. Uses
//! `gloo-net` (built on `fetch`), which works in the browser and avoids the
//! `tokio` dependency the rest of the WASM bundle can't link.

use anyhow::{anyhow, Result};
use gloo_net::http::{Request, Response};
use serde::de::DeserializeOwned;
use viche_core::wire::{
    CommitmentListResponse, PollData, PollListResponse, PublishRegistrationRequest,
    PublishRegistrationResponse, RegisterRequest, RegisterResponse, TallyResponse, VoteRequest,
    VoteResponse,
};

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

    /// `POST /api/admin/registrations/snapshot` — owner-only. Locks in the
    /// current pending batch and returns it.
    pub async fn snapshot_registrations(
        &self,
        admin_api_key: &str,
    ) -> Result<Vec<alloy_primitives::U256>> {
        let url = format!("{}/api/admin/registrations/snapshot", self.base);
        let resp = Request::post(&url)
            .header("Authorization", &format!("Bearer {}", admin_api_key))
            .send()
            .await
            .map_err(|e| anyhow!("POST {} failed: {:?}", url, e))?;
        let body: CommitmentListResponse =
            Self::decode_or_error(resp, "POST /api/admin/registrations/snapshot").await?;
        Ok(body.commitments)
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
