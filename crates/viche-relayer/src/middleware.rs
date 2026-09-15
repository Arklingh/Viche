//! HTTP middleware: client-IP resolution, per-IP rate limiting, load
//! shedding, CORS, and response security headers.
//!
//! ## Production topology this assumes
//!
//! ```text
//!   browser ──TLS──> reverse proxy (nginx/Caddy/ALB) ──HTTP──> viche-relayer
//!                     │  serves the Trunk-built SPA at  /
//!                     └─ proxies                        /api/* and /health
//! ```
//!
//! Because the SPA and the API are served from **one origin**, nothing needs
//! CORS in that topology — which is why `CORS_ALLOWED_ORIGINS` defaults to
//! empty (no cross-origin access at all) rather than `*`. Set it only when
//! the SPA genuinely lives on a different origin from the relayer.
//!
//! The same proxy is why client-IP extraction is configurable. Behind a
//! proxy, the socket peer address is the *proxy's* address, so every request
//! would share one rate-limit bucket. But trusting `X-Forwarded-For`
//! unconditionally is worse: anyone could then forge a fresh IP per request
//! and defeat the limiter entirely. So `TRUST_PROXY_HEADERS` defaults to
//! `false` (use the socket peer), and when it is enabled `TRUSTED_PROXY_HOPS`
//! says how many trailing entries of the forwarded chain are hops you
//! actually control — only those are skipped. See [`client_ip`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::config::HttpConfig;
use crate::error::ApiError;
use crate::ratelimit::{RateLimitDecision, RateLimiter};

/// The client IP a request was attributed to, inserted into request
/// extensions by [`resolve_client_ip`] and read back by the rate limiter and
/// the registration handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// Fallback when neither a forwarded header nor a `ConnectInfo` is present
/// (which in practice means a test harness or a unix-socket listener).
/// Deliberately a real, routable-looking address so every such request lands
/// in one shared bucket rather than being silently unlimited.
const UNKNOWN_CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Header carrying the invite code for `POST /api/register`.
///
/// A header rather than a body field so the shared `viche-core` wire type
/// (`RegisterRequest`) stays untouched — deployers who run an open or
/// allowlist policy never send it, and the browser sets it trivially.
pub const INVITE_CODE_HEADER: &str = "x-invite-code";

/// Decide which IP to attribute a request to.
///
/// * `trust_proxy = false` — always the socket peer. Forwarded headers are
///   ignored entirely, so they cannot be used to evade the rate limiter.
/// * `trust_proxy = true` — walk the forwarded chain
///   `[xff_0, xff_1, …, xff_n, peer]` and take the entry `hops` places from
///   the right, i.e. the last address that a proxy we do *not* control could
///   not have chosen. With one trusted proxy (`hops = 1`) that is the final
///   `X-Forwarded-For` entry; with two it is the one before it.
///
/// Anything unparseable falls back to `peer`, never to a client-controlled
/// value.
pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    trust_proxy: bool,
    hops: usize,
) -> IpAddr {
    let peer_ip = peer.unwrap_or(UNKNOWN_CLIENT_IP);
    if !trust_proxy {
        return peer_ip;
    }

    // Build the full chain: every X-Forwarded-For entry (in order, possibly
    // spread across repeated headers) followed by the socket peer.
    let mut chain: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(parse_forwarded_ip)
        .collect();

    if chain.is_empty() {
        // Some proxies send only X-Real-IP. Honour it as a single hop.
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_forwarded_ip)
        {
            chain.push(ip);
        }
    }

    chain.push(peer_ip);

    let hops = hops.max(1);
    let idx = chain.len().saturating_sub(hops + 1);
    chain.get(idx).copied().unwrap_or(peer_ip)
}

/// Parse one `X-Forwarded-For` list element.
///
/// Handles the bare-IP form and the `[v6]:port` / `v4:port` forms some
/// proxies emit. Returns `None` for anything else (including the `unknown`
/// token and obfuscated `_id` identifiers RFC 7239 permits).
fn parse_forwarded_ip(raw: &str) -> Option<IpAddr> {
    let s = raw.trim().trim_matches('"');
    if s.is_empty() {
        return None;
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sock) = s.parse::<SocketAddr>() {
        return Some(sock.ip());
    }
    // Bracketed IPv6 without a port, e.g. "[2001:db8::1]".
    if let Some(inner) = s.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if let Ok(ip) = inner.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

/// Proxy-trust settings, shared with the client-IP middleware.
#[derive(Debug, Clone, Copy)]
pub struct ProxyConfig {
    /// See [`HttpConfig::trust_proxy_headers`].
    pub trust_proxy_headers: bool,
    /// See [`HttpConfig::trusted_proxy_hops`].
    pub trusted_proxy_hops: usize,
}

/// Middleware: resolve the client IP once, up front, and stash it in the
/// request extensions so everything downstream agrees on the answer.
pub async fn resolve_client_ip(
    State(cfg): State<ProxyConfig>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let ip = client_ip(
        req.headers(),
        peer,
        cfg.trust_proxy_headers,
        cfg.trusted_proxy_hops,
    );
    req.extensions_mut().insert(ClientIp(ip));
    next.run(req).await
}

/// Middleware: enforce one [`RateLimiter`] against the resolved client IP.
///
/// CORS preflights are exempt — they carry no body, cost nothing, and
/// rejecting one produces a confusing browser-side CORS failure rather than
/// a visible 429.
pub async fn rate_limit(
    State(limiter): State<Arc<RateLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }

    let ip = req
        .extensions()
        .get::<ClientIp>()
        .copied()
        .unwrap_or(ClientIp(UNKNOWN_CLIENT_IP));

    match limiter.check(ip.0) {
        RateLimitDecision::Allowed => next.run(req).await,
        RateLimitDecision::Limited { retry_after_secs } => {
            // Log the path but never the body or the resolved IP: a log line
            // pairing an IP with `POST /api/vote` is already more linkage
            // than this system should emit.
            tracing::debug!(path = %req.uri().path(), "request rate-limited");
            rate_limited_response(retry_after_secs)
        }
    }
}

fn rate_limited_response(retry_after_secs: u64) -> Response {
    let body = ApiError {
        code: "RATE_LIMITED",
        message: format!("too many requests; retry in {retry_after_secs}s"),
    };
    let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, value);
    }
    resp
}

/// Shared in-flight-request budget for [`concurrency_limit`].
#[derive(Debug, Clone)]
pub struct ConcurrencyGuard(Arc<Semaphore>);

impl ConcurrencyGuard {
    /// Allow at most `max` requests to be in flight at once.
    pub fn new(max: usize) -> Self {
        Self(Arc::new(Semaphore::new(max.max(1))))
    }

    /// Take a permit, or `None` if the budget is exhausted.
    fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.0).try_acquire_owned().ok()
    }

    /// Permits currently free. Test/metrics helper.
    pub fn available(&self) -> usize {
        self.0.available_permits()
    }
}

/// Middleware: shed load past the configured in-flight ceiling.
///
/// Deliberately *sheds* (503 + `Retry-After: 1`) rather than queueing. Axum
/// spawns a task per request, so queueing behind a semaphore would let a
/// hung RPC backend accumulate unbounded parked tasks — precisely the
/// failure this is meant to prevent.
pub async fn concurrency_limit(
    State(guard): State<ConcurrencyGuard>,
    req: Request,
    next: Next,
) -> Response {
    let Some(permit) = guard.try_acquire() else {
        tracing::warn!(path = %req.uri().path(), "in-flight request limit reached; shedding");
        let body = ApiError {
            code: "OVERLOADED",
            message: "the relayer is at capacity; please retry shortly".into(),
        };
        let mut resp = (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    };

    let response = next.run(req).await;
    drop(permit);
    response
}

/// Build the CORS layer from the configured origin allowlist.
///
/// An empty allowlist yields a layer that permits no cross-origin request at
/// all — correct for the same-origin reverse-proxy topology in the module
/// docs. Credentials are never enabled: the API authenticates with a bearer
/// header, not cookies, so `Access-Control-Allow-Credentials` would only add
/// CSRF surface.
pub fn cors_layer(cfg: &HttpConfig) -> CorsLayer {
    let origins: Vec<HeaderValue> = cfg
        .cors_allowed_origins
        .iter()
        .filter_map(|o| match HeaderValue::from_str(o) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::warn!(origin = %o, "ignoring unparseable CORS origin");
                None
            }
        })
        .collect();

    if origins.is_empty() {
        tracing::info!(
            "CORS: no origins allowed (same-origin only). Set CORS_ALLOWED_ORIGINS if the \
             frontend is served from a different origin than the relayer."
        );
        // `CorsLayer::new()` with no allowed origin emits no
        // `Access-Control-Allow-Origin`, so browsers block every
        // cross-origin read. Same-origin requests are unaffected.
        return CorsLayer::new();
    }

    tracing::info!(origins = ?cfg.cors_allowed_origins, "CORS: allowing listed origins");
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static(INVITE_CODE_HEADER),
        ])
        .max_age(std::time::Duration::from_secs(600))
}

/// Response headers that make sense for a JSON-only API.
///
/// No CSP `script-src` gymnastics — nothing here is ever rendered as a
/// document — but `nosniff` plus a locked-down `default-src 'none'` closes
/// the "browser is tricked into treating a JSON error body as HTML" family,
/// `frame-ancestors 'none'`/`DENY` closes clickjacking on any future
/// non-JSON route, `no-referrer` stops poll ids leaking to third parties via
/// the `Referer` header, and `no-store` keeps vote and registration
/// responses out of intermediary caches.
pub fn security_header_layers() -> [SetResponseHeaderLayer<HeaderValue>; 5] {
    [
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; sandbox"),
        ),
        SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ),
    ]
}

/// Read the invite code a request carries, if any.
pub fn invite_code(headers: &HeaderMap) -> Option<String> {
    headers
        .get(INVITE_CODE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn headers_with(name: &'static str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(HeaderName::from_static(name), value.parse().unwrap());
        h
    }

    // ---- client_ip: proxy trust disabled ---------------------------------

    #[test]
    fn untrusted_mode_always_uses_the_socket_peer() {
        let headers = headers_with("x-forwarded-for", "1.2.3.4");
        let peer = v4(203, 0, 113, 9);
        assert_eq!(client_ip(&headers, Some(peer), false, 1), peer);
    }

    #[test]
    fn untrusted_mode_ignores_a_forged_chain() {
        // The classic limiter-evasion attempt: a fresh fake IP per request.
        let headers = headers_with("x-forwarded-for", "9.9.9.9, 8.8.8.8, 7.7.7.7");
        let peer = v4(203, 0, 113, 9);
        assert_eq!(client_ip(&headers, Some(peer), false, 3), peer);
    }

    #[test]
    fn falls_back_to_a_fixed_address_when_there_is_no_peer() {
        let headers = HeaderMap::new();
        assert_eq!(client_ip(&headers, None, false, 1), UNKNOWN_CLIENT_IP);
    }

    // ---- client_ip: proxy trust enabled ----------------------------------

    #[test]
    fn one_trusted_hop_takes_the_last_forwarded_entry() {
        // chain = [1.1.1.1, 2.2.2.2, peer]; skip 1 hop (the proxy = peer).
        let headers = headers_with("x-forwarded-for", "1.1.1.1, 2.2.2.2");
        let peer = v4(10, 0, 0, 1);
        assert_eq!(client_ip(&headers, Some(peer), true, 1), v4(2, 2, 2, 2));
    }

    #[test]
    fn two_trusted_hops_skip_one_more_entry() {
        let headers = headers_with("x-forwarded-for", "1.1.1.1, 2.2.2.2, 3.3.3.3");
        let peer = v4(10, 0, 0, 1);
        // chain = [1.1.1.1, 2.2.2.2, 3.3.3.3, peer]; skip 2 => 2.2.2.2.
        assert_eq!(client_ip(&headers, Some(peer), true, 2), v4(2, 2, 2, 2));
    }

    #[test]
    fn a_short_chain_cannot_be_walked_past_its_left_edge() {
        // Only one entry but three claimed hops: clamp to the leftmost
        // rather than panicking or wrapping.
        let headers = headers_with("x-forwarded-for", "1.1.1.1");
        let peer = v4(10, 0, 0, 1);
        assert_eq!(client_ip(&headers, Some(peer), true, 3), v4(1, 1, 1, 1));
    }

    #[test]
    fn trusted_mode_with_no_forwarded_header_falls_back_to_the_peer() {
        let headers = HeaderMap::new();
        let peer = v4(10, 0, 0, 1);
        assert_eq!(client_ip(&headers, Some(peer), true, 1), peer);
    }

    #[test]
    fn trusted_mode_honours_x_real_ip_when_xff_is_absent() {
        let headers = headers_with("x-real-ip", "198.51.100.7");
        let peer = v4(10, 0, 0, 1);
        assert_eq!(
            client_ip(&headers, Some(peer), true, 1),
            v4(198, 51, 100, 7)
        );
    }

    #[test]
    fn x_real_ip_is_ignored_when_xff_is_present() {
        let mut headers = headers_with("x-forwarded-for", "1.1.1.1");
        headers.insert(
            HeaderName::from_static("x-real-ip"),
            "9.9.9.9".parse().unwrap(),
        );
        let peer = v4(10, 0, 0, 1);
        assert_eq!(client_ip(&headers, Some(peer), true, 1), v4(1, 1, 1, 1));
    }

    #[test]
    fn repeated_forwarded_headers_are_concatenated_in_order() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_static("x-forwarded-for"),
            "1.1.1.1".parse().unwrap(),
        );
        headers.append(
            HeaderName::from_static("x-forwarded-for"),
            "2.2.2.2".parse().unwrap(),
        );
        let peer = v4(10, 0, 0, 1);
        assert_eq!(client_ip(&headers, Some(peer), true, 1), v4(2, 2, 2, 2));
    }

    #[test]
    fn garbage_entries_are_dropped_from_the_chain() {
        let headers = headers_with("x-forwarded-for", "unknown, _hidden, 2.2.2.2");
        let peer = v4(10, 0, 0, 1);
        assert_eq!(client_ip(&headers, Some(peer), true, 1), v4(2, 2, 2, 2));
    }

    #[test]
    fn an_all_garbage_chain_falls_back_to_the_peer() {
        let headers = headers_with("x-forwarded-for", "unknown, _obfuscated");
        let peer = v4(10, 0, 0, 1);
        assert_eq!(client_ip(&headers, Some(peer), true, 1), peer);
    }

    // ---- parse_forwarded_ip ---------------------------------------------

    #[test]
    fn parses_bare_ipv4_ipv6_and_port_suffixed_forms() {
        assert_eq!(parse_forwarded_ip(" 1.2.3.4 "), Some(v4(1, 2, 3, 4)));
        assert_eq!(parse_forwarded_ip("1.2.3.4:8080"), Some(v4(1, 2, 3, 4)));
        assert_eq!(
            parse_forwarded_ip("2001:db8::1"),
            Some(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
        );
        assert_eq!(
            parse_forwarded_ip("[2001:db8::1]:443"),
            Some(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
        );
        assert_eq!(
            parse_forwarded_ip("[2001:db8::1]"),
            Some(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
        );
    }

    #[test]
    fn rejects_non_addresses() {
        assert_eq!(parse_forwarded_ip(""), None);
        assert_eq!(parse_forwarded_ip("unknown"), None);
        assert_eq!(parse_forwarded_ip("_secret"), None);
        assert_eq!(parse_forwarded_ip("example.com"), None);
    }

    // ---- invite_code ----------------------------------------------------

    #[test]
    fn invite_code_reads_and_trims_the_header() {
        let headers = headers_with("x-invite-code", "  spring-2026  ");
        assert_eq!(invite_code(&headers), Some("spring-2026".to_string()));
    }

    #[test]
    fn invite_code_is_none_when_absent_or_blank() {
        assert_eq!(invite_code(&HeaderMap::new()), None);
        assert_eq!(invite_code(&headers_with("x-invite-code", "   ")), None);
    }

    // ---- ConcurrencyGuard ------------------------------------------------

    #[test]
    fn concurrency_guard_hands_out_exactly_max_permits() {
        let guard = ConcurrencyGuard::new(2);
        let a = guard.try_acquire();
        let b = guard.try_acquire();
        assert!(a.is_some() && b.is_some());
        assert!(guard.try_acquire().is_none());
        assert_eq!(guard.available(), 0);

        drop(a);
        assert_eq!(guard.available(), 1);
        assert!(guard.try_acquire().is_some());
        drop(b);
    }

    #[test]
    fn concurrency_guard_never_allows_a_zero_budget() {
        // A misconfigured 0 would deadlock the service; clamp to 1.
        let guard = ConcurrencyGuard::new(0);
        assert!(guard.try_acquire().is_some());
    }

    // ---- cors_layer ------------------------------------------------------

    #[test]
    fn cors_layer_builds_for_an_empty_and_a_populated_allowlist() {
        let mut cfg = test_http_config();
        let _ = cors_layer(&cfg);
        cfg.cors_allowed_origins = vec!["https://vote.example.org".into()];
        let _ = cors_layer(&cfg);
    }

    fn test_http_config() -> HttpConfig {
        use crate::config::RateLimitRule;
        let rule = RateLimitRule {
            per_minute: 60,
            burst: 10,
        };
        HttpConfig {
            cors_allowed_origins: Vec::new(),
            trust_proxy_headers: false,
            trusted_proxy_hops: 1,
            rate_limit_vote: rule,
            rate_limit_register: rule,
            rate_limit_read: rule,
            rate_limit_admin: rule,
            rate_limit_max_tracked_ips: 1000,
            max_vote_body_bytes: 4096,
            max_register_body_bytes: 1024,
            max_admin_body_bytes: 65536,
            max_body_bytes: 16384,
            request_timeout: std::time::Duration::from_secs(20),
            max_concurrent_requests: 64,
        }
    }

    #[test]
    fn security_headers_cover_the_expected_set() {
        // Compile-time guarantee on the count; the values themselves are
        // asserted end-to-end in handlers.rs's router tests.
        assert_eq!(security_header_layers().len(), 5);
    }
}
