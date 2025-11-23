use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
use reqwest::StatusCode;

const RATE_LIMIT_LIMIT: &str = "X-RateLimit-Limit";
const RATE_LIMIT_REMAINING: &str = "X-RateLimit-Remaining";
const RATE_LIMIT_RESET: &str = "X-RateLimit-Reset";

/// Snapshot of the latest rate-limit headers returned by the RPC.
///
/// The helper normalizes the reset window so SDKs can schedule backoff using the
/// same semantics as the server: the reset value is measured in seconds until at
/// least one token becomes available again. When the header is missing or zero,
/// a caller-supplied floor is used so backoff never collapses to a busy loop.
///
/// ```rust
/// use std::time::Duration;
/// use reqwest::header::{HeaderMap, HeaderValue};
/// use rpp_chain_cli::rate_limit::rate_limit_window;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("X-RateLimit-Limit", HeaderValue::from_static("10"));
/// headers.insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));
/// headers.insert("X-RateLimit-Reset", HeaderValue::from_static("3"));
///
/// let window = rate_limit_window(&headers, Duration::from_millis(50));
/// assert_eq!(window.limit, Some(10));
/// assert_eq!(window.remaining, Some(0));
/// assert_eq!(window.reset_after, Duration::from_secs(3));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitWindow {
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset_after: Duration,
}

/// Extract a rate-limit window description from HTTP headers.
pub fn rate_limit_window(headers: &HeaderMap, floor: Duration) -> RateLimitWindow {
    let parse_u64 = |value: Option<&HeaderValue>| {
        value
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
    };

    let limit = parse_u64(headers.get(RATE_LIMIT_LIMIT));
    let remaining = parse_u64(headers.get(RATE_LIMIT_REMAINING));
    let reset_after = parse_u64(headers.get(RATE_LIMIT_RESET))
        .map(Duration::from_secs)
        .unwrap_or(floor)
        .max(floor);

    RateLimitWindow {
        limit,
        remaining,
        reset_after,
    }
}

/// Compute how long to wait before retrying a rate-limited request.
///
/// The helper looks for `X-RateLimit-Reset` first and falls back to the standard
/// `Retry-After` header. Both values are clamped to `floor` so callers always
/// pause for at least a minimal backoff.
///
/// ```rust
/// use std::time::Duration;
/// use reqwest::header::{HeaderMap, HeaderValue};
/// use reqwest::StatusCode;
/// use rpp_chain_cli::rate_limit::compute_retry_delay;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("X-RateLimit-Reset", HeaderValue::from_static("1"));
/// headers.insert("Retry-After", HeaderValue::from_static("2"));
///
/// let delay = compute_retry_delay(StatusCode::TOO_MANY_REQUESTS, &headers, Duration::from_millis(10));
/// assert_eq!(delay, Duration::from_secs(1));
///
/// // When reset is missing the helper falls back to Retry-After.
/// headers.remove("X-RateLimit-Reset");
/// let delay = compute_retry_delay(StatusCode::TOO_MANY_REQUESTS, &headers, Duration::from_millis(10));
/// assert_eq!(delay, Duration::from_secs(2));
/// ```
pub fn compute_retry_delay(status: StatusCode, headers: &HeaderMap, floor: Duration) -> Duration {
    if status == StatusCode::TOO_MANY_REQUESTS {
        let window = rate_limit_window(headers, floor);
        return window.reset_after;
    }

    parse_retry_after(headers, floor)
}

fn parse_retry_after(headers: &HeaderMap, floor: Duration) -> Duration {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(floor)
        .max(floor)
}
