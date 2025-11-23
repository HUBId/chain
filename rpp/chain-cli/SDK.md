# SDK rate limit handling

The RPC returns standard HTTP rate-limit headers when a request is throttled.
Clients should use the values to throttle themselves instead of hammering the
server with blind retries. The helpers exported by `rpp-chain-cli` mirror the
server semantics so SDKs can share the same backoff behavior.

## Inspect the headers

Use `rate_limit_window` to read the limit, the remaining budget, and the reset
interval expressed in seconds until a token becomes available again.

```rust
use std::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue};
use rpp_chain_cli::rate_limit::rate_limit_window;

let mut headers = HeaderMap::new();
headers.insert("X-RateLimit-Limit", HeaderValue::from_static("120"));
headers.insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));
headers.insert("X-RateLimit-Reset", HeaderValue::from_static("1"));

let window = rate_limit_window(&headers, Duration::from_millis(25));
assert_eq!(window.limit, Some(120));
assert_eq!(window.remaining, Some(0));
assert_eq!(window.reset_after, Duration::from_secs(1));
```

## Back off before retrying

The `compute_retry_delay` helper prioritizes `X-RateLimit-Reset` and falls back
to `Retry-After` so clients match the server’s token-bucket semantics. The
returned delay is clamped to a caller-provided floor to avoid tight loops even
when a proxy strips headers.

```rust
use std::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;
use rpp_chain_cli::rate_limit::{compute_retry_delay, rate_limit_window};
use tokio::runtime::Runtime;
use tokio::time::sleep;

let mut headers = HeaderMap::new();
headers.insert("X-RateLimit-Reset", HeaderValue::from_static("0"));
headers.insert("Retry-After", HeaderValue::from_static("2"));

let rt = Runtime::new().unwrap();
rt.block_on(async {
    let window = rate_limit_window(&headers, Duration::from_millis(20));
    let delay = compute_retry_delay(StatusCode::TOO_MANY_REQUESTS, &headers, Duration::from_millis(20));

    // Respect the advertised window before sending the next request.
    sleep(delay).await;

    // Your retry goes here; the example just checks the delay.
    assert!(delay >= window.reset_after);
});
```
