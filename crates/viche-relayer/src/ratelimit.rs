//! Per-IP token-bucket rate limiting.
//!
//! ## Why a hand-rolled limiter
//!
//! The relayer needs four *independently tuned* buckets (vote, register,
//! admin, read) keyed by a client IP that is itself derived from a
//! configurable proxy-trust policy (see [`crate::middleware::client_ip`]).
//! A token bucket is ~60 lines, has no dependency, and — crucially — can be
//! driven by an injected `Instant` so the whole thing is unit-testable
//! without sleeping in tests.
//!
//! ## Semantics
//!
//! Each key gets a bucket of `burst` tokens that refills continuously at
//! `per_minute / 60` tokens per second and never exceeds `burst`. A request
//! costs one token. If fewer than one token is available the request is
//! rejected with the wall-clock seconds until one will be.
//!
//! ## Bounded memory
//!
//! An attacker who can influence the key (by forging `X-Forwarded-For` when
//! `TRUST_PROXY_HEADERS=true`, or simply by rotating through an IPv6 /64)
//! would otherwise grow the bucket map without bound — turning a rate
//! limiter into a memory-exhaustion vector. So the map is capped at
//! `max_tracked`: on insert, once the cap is hit, buckets that have fully
//! refilled (i.e. their owner is no longer rate-limited, so forgetting them
//! changes nothing) are evicted first, and if that frees nothing the new key
//! is simply not tracked and the request is allowed. Allowing is the right
//! failure mode here: the concurrency limit and request timeout are the
//! backstop for raw volume, and silently dropping legitimate traffic because
//! of an unrelated flood would be worse.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use crate::config::RateLimitRule;

/// The outcome of a single rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Under the limit — proceed.
    Allowed,
    /// Over the limit. Carries the `Retry-After` value in whole seconds
    /// (always at least 1, since `Retry-After: 0` reads as "retry now").
    Limited { retry_after_secs: u64 },
}

impl RateLimitDecision {
    /// Whether the request may proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Tokens remaining as of `last_seen`.
    tokens: f64,
    last_seen: Instant,
}

/// A per-key token-bucket rate limiter.
///
/// Cheap to share: wrap in an `Arc` and clone the handle into every layer
/// that needs it. Internally a single `Mutex<HashMap<..>>`, which is fine at
/// this scale — the critical section is a few float operations.
#[derive(Debug)]
pub struct RateLimiter {
    rule: RateLimitRule,
    max_tracked: usize,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    /// Build a limiter enforcing `rule`, tracking at most `max_tracked`
    /// distinct keys.
    pub fn new(rule: RateLimitRule, max_tracked: usize) -> Self {
        Self {
            rule,
            max_tracked: max_tracked.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Check (and consume) one token for `key`, using the current time.
    pub fn check(&self, key: IpAddr) -> RateLimitDecision {
        self.check_at(key, Instant::now())
    }

    /// Check (and consume) one token for `key` as of `now`.
    ///
    /// Split out from [`Self::check`] purely so tests can advance time
    /// without sleeping.
    pub fn check_at(&self, key: IpAddr, now: Instant) -> RateLimitDecision {
        let capacity = f64::from(self.rule.burst);
        let refill = self.rule.refill_per_second();

        let mut buckets = match self.buckets.lock() {
            Ok(g) => g,
            // A panic while holding the lock can only come from this module,
            // which does no allocation-fallible or panicking work inside the
            // critical section. Recover rather than cascade the panic into
            // every subsequent request.
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(bucket) = buckets.get_mut(&key) {
            // Refill for the elapsed time, saturating at capacity.
            let elapsed = now.saturating_duration_since(bucket.last_seen).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * refill).min(capacity);
            bucket.last_seen = now;

            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                return RateLimitDecision::Allowed;
            }
            let deficit = 1.0 - bucket.tokens;
            return RateLimitDecision::Limited {
                retry_after_secs: (deficit / refill).ceil().max(1.0) as u64,
            };
        }

        // First request from this key: needs a new bucket.
        if buckets.len() >= self.max_tracked {
            evict_refilled(&mut buckets, capacity, refill, now);
            if buckets.len() >= self.max_tracked {
                // Still full — don't track, don't block. See the module
                // docs on why allowing is the right failure mode.
                tracing::warn!(
                    tracked = buckets.len(),
                    "rate-limiter key table is full; request allowed untracked"
                );
                return RateLimitDecision::Allowed;
            }
        }

        buckets.insert(
            key,
            Bucket {
                tokens: capacity - 1.0,
                last_seen: now,
            },
        );
        RateLimitDecision::Allowed
    }

    /// Number of keys currently tracked. Test/metrics helper.
    pub fn tracked_keys(&self) -> usize {
        match self.buckets.lock() {
            Ok(g) => g.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }
}

/// Drop every bucket that has refilled back to capacity as of `now`.
///
/// Such a key is indistinguishable from one we have never seen, so removing
/// it loses no enforcement — it just frees the slot.
fn evict_refilled(
    buckets: &mut HashMap<IpAddr, Bucket>,
    capacity: f64,
    refill: f64,
    now: Instant,
) {
    buckets.retain(|_, bucket| {
        let elapsed = now.saturating_duration_since(bucket.last_seen).as_secs_f64();
        bucket.tokens + elapsed * refill < capacity
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn rule(per_minute: u32, burst: u32) -> RateLimitRule {
        RateLimitRule { per_minute, burst }
    }

    #[test]
    fn allows_up_to_the_burst_then_limits() {
        let limiter = RateLimiter::new(rule(60, 3), 1000);
        let t0 = Instant::now();

        for i in 0..3 {
            assert_eq!(
                limiter.check_at(ip(1), t0),
                RateLimitDecision::Allowed,
                "request {i} should be inside the burst"
            );
        }
        assert!(matches!(
            limiter.check_at(ip(1), t0),
            RateLimitDecision::Limited { .. }
        ));
    }

    #[test]
    fn buckets_are_independent_per_ip() {
        let limiter = RateLimiter::new(rule(60, 1), 1000);
        let t0 = Instant::now();

        assert!(limiter.check_at(ip(1), t0).is_allowed());
        assert!(!limiter.check_at(ip(1), t0).is_allowed());
        // A different IP still has a full bucket.
        assert!(limiter.check_at(ip(2), t0).is_allowed());
    }

    #[test]
    fn refills_over_time() {
        // 60/minute = 1 token per second.
        let limiter = RateLimiter::new(rule(60, 2), 1000);
        let t0 = Instant::now();

        assert!(limiter.check_at(ip(1), t0).is_allowed());
        assert!(limiter.check_at(ip(1), t0).is_allowed());
        assert!(!limiter.check_at(ip(1), t0).is_allowed());

        // One second later exactly one token is back.
        let t1 = t0 + Duration::from_secs(1);
        assert!(limiter.check_at(ip(1), t1).is_allowed());
        assert!(!limiter.check_at(ip(1), t1).is_allowed());
    }

    #[test]
    fn refill_never_exceeds_the_burst_capacity() {
        let limiter = RateLimiter::new(rule(60, 2), 1000);
        let t0 = Instant::now();
        assert!(limiter.check_at(ip(1), t0).is_allowed());

        // An hour of idling must not bank 3600 tokens.
        let t1 = t0 + Duration::from_secs(3600);
        assert!(limiter.check_at(ip(1), t1).is_allowed());
        assert!(limiter.check_at(ip(1), t1).is_allowed());
        assert!(!limiter.check_at(ip(1), t1).is_allowed());
    }

    #[test]
    fn retry_after_is_at_least_one_second() {
        // 6/minute = 0.1 tokens/sec, so the true wait is 10s.
        let limiter = RateLimiter::new(rule(6, 1), 1000);
        let t0 = Instant::now();
        assert!(limiter.check_at(ip(1), t0).is_allowed());

        match limiter.check_at(ip(1), t0) {
            RateLimitDecision::Limited { retry_after_secs } => {
                assert_eq!(retry_after_secs, 10);
            }
            other => panic!("expected Limited, got {other:?}"),
        }

        // And a very fast rule still never reports 0.
        let fast = RateLimiter::new(rule(6000, 1), 1000);
        assert!(fast.check_at(ip(1), t0).is_allowed());
        match fast.check_at(ip(1), t0) {
            RateLimitDecision::Limited { retry_after_secs } => assert_eq!(retry_after_secs, 1),
            other => panic!("expected Limited, got {other:?}"),
        }
    }

    #[test]
    fn evicts_refilled_buckets_when_the_table_is_full() {
        let limiter = RateLimiter::new(rule(60, 1), 2);
        let t0 = Instant::now();

        assert!(limiter.check_at(ip(1), t0).is_allowed());
        assert!(limiter.check_at(ip(2), t0).is_allowed());
        assert_eq!(limiter.tracked_keys(), 2);

        // A minute later both are fully refilled, so a third key evicts them.
        let t1 = t0 + Duration::from_secs(60);
        assert!(limiter.check_at(ip(3), t1).is_allowed());
        assert_eq!(limiter.tracked_keys(), 1);
    }

    #[test]
    fn a_full_table_of_active_buckets_allows_rather_than_blocks_new_keys() {
        let limiter = RateLimiter::new(rule(1, 1), 1);
        let t0 = Instant::now();

        // ip(1) takes the only slot and is now limited.
        assert!(limiter.check_at(ip(1), t0).is_allowed());
        assert!(!limiter.check_at(ip(1), t0).is_allowed());

        // ip(2) can't be tracked, but must not inherit ip(1)'s limit.
        assert!(limiter.check_at(ip(2), t0).is_allowed());
        assert_eq!(limiter.tracked_keys(), 1);
    }

    #[test]
    fn an_existing_key_is_still_enforced_when_the_table_is_full() {
        let limiter = RateLimiter::new(rule(1, 1), 1);
        let t0 = Instant::now();
        assert!(limiter.check_at(ip(1), t0).is_allowed());
        // Tracked keys are enforced regardless of table pressure.
        assert!(!limiter.check_at(ip(1), t0).is_allowed());
        assert!(!limiter.check_at(ip(1), t0).is_allowed());
    }
}
