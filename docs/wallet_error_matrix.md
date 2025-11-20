# Wallet error matrix

This matrix links JSON-RPC error codes to likely causes, recommended operator
actions, and the GUI surfaces that present the friendly text. Keep it in sync
with the Phase 3 GUI dictionary and the message catalog under
`rpp/wallet/wallet_messages.toml`.【F:docs/wallet_phase3_gui.md†L89-L113】【F:docs/wallet/operations.md†L16-L41】

| RPC code | Typical cause | GUI/CLI surface | Operator action |
| --- | --- | --- | --- |
| `-32700 parse error` | Malformed JSON payload | CLI stderr, GUI toast | Reissue the request with valid JSON.【F:docs/wallet_phase1_minimal.md†L98-L117】 |
| `-32600 invalid request` | Missing fields or wrong JSON-RPC version | CLI stderr, GUI toast | Fix request shape; confirm `jsonrpc: "2.0"`.【F:docs/wallet_phase1_minimal.md†L98-L117】 |
| `-32601 method not found` | Calling an unsupported RPC | CLI stderr, GUI toast | Check method spelling/version; upgrade client.【F:docs/wallet_phase1_minimal.md†L98-L117】 |
| `-32602 invalid params` | Param type/shape mismatch | CLI stderr, Send tab banner | Rebuild request with correct parameter types.【F:docs/wallet_phase1_minimal.md†L98-L117】 |
| `-32603 internal error` | Serialization or poisoned state | CLI stderr, Overview tab toast | Inspect wallet logs; restart runtime.【F:docs/wallet_phase1_minimal.md†L98-L117】 |
| `-32010 wallet error` / `wallet::errors::InsufficientFunds` | Spend exceeds balance | Send tab banner | Lower amount or wait for confirmations.【F:docs/wallet_phase3_gui.md†L89-L109】 |
| `-32010 wallet error` / `wallet::errors::PolicyViolation` | Draft violates tiered policy | Send tab inline validation | Adjust draft; update policy if needed.【F:docs/wallet_phase3_gui.md†L89-L109】【F:docs/wallet/operations.md†L7-L19】 |
| `-32010 wallet error` / `wallet::errors::LockConflict` | Inputs locked by another session | Send tab modal | Release locks via CLI or wait for timeout.【F:docs/wallet_phase3_gui.md†L89-L109】 |
| `-32010 wallet error` / `wallet::errors::ProverTimeout` | Proof backend exceeded timeout | Send tab banner, Prover tab row | Increase `[wallet.prover].timeout_secs` or inspect prover logs.【F:docs/wallet_phase3_gui.md†L103-L110】【F:config/wallet.toml†L125-L132】 |
| `-32020 sync error` | Sync driver failure | Overview tab toast | Review sync logs; reschedule with `rescan`.【F:docs/wallet_phase1_minimal.md†L136-L154】 |
| `-32030 node error` | Broadcast failed in node | Send tab banner | Retry after node recovers; check node logs.【F:docs/wallet_phase1_minimal.md†L155-L185】 |
| `-32040 draft not found` | Signing/broadcasting unknown draft | Send tab banner | Recreate draft before signing.【F:docs/wallet_phase1_minimal.md†L155-L185】 |
| `-32041 draft unsigned` | Broadcast attempted before signing | Send tab banner | Sign the draft, verify proof required flag.【F:docs/wallet_phase1_minimal.md†L155-L185】【F:config/wallet.toml†L125-L132】 |
| `-32050 sync unavailable` | Sync disabled or coordinator missing | Overview tab toast | Enable sync, check coordinator config.【F:docs/wallet_phase1_minimal.md†L117-L135】 |
| `-32051 rescan out of range` | Requested height predates indexed range | Overview tab toast | Pick a later start height; adjust `lookback_blocks`.【F:docs/wallet_phase1_minimal.md†L117-L135】【F:config/wallet.toml†L95-L102】 |
| `-32060 unauthorized` | Missing/invalid bearer token | CLI stderr, GUI modal | Provide valid token; confirm `wallet.auth`/mTLS settings.【F:docs/wallet_phase1_minimal.md†L98-L117】【F:docs/wallet_phase4_advanced.md†L124-L158】 |
| `-32061 rate limited` | Per-minute budget exceeded | CLI stderr, GUI toast | Back off and tune `[wallet.rpc].requests_per_minute` or `[wallet.budgets]`.【F:docs/wallet_phase1_minimal.md†L98-L117】【F:config/wallet.toml†L35-L53】 |

When customizing `wallet_messages.toml`, keep the codes and keys intact so the
GUI mapping remains stable across releases.【F:docs/wallet/operations.md†L16-L41】
