# rpp-wallet

The `rpp-wallet` crate bundles the wallet runtime, JSON-RPC surface, and CLI used by RPP operators. It shares storage and configuration conventions with the hybrid runtime so node operators can co-locate services.

## Phase 2: What's new

Phase 2 introduces policy, fee, locking, and prover upgrades that require operator attention.【F:docs/wallet_phase2_policies_prover.md†L1-L71】 Highlights include:

* **Configurable spend policies** – Tune gap limits, minimum confirmations, dust limits, and daily spend caps via `wallet.policy.*`, and persist signed policy statements over RPC or `rpp-wallet policy set`.【F:docs/wallet_phase2_policies_prover.md†L5-L17】
* **Fee estimator revamp** – Automatic congestion-aware quotes with override validation and caching; use `rpp-wallet fees estimate` to sample current guidance before a send.【F:docs/wallet_phase2_policies_prover.md†L18-L27】
* **Pending lock tooling** – Deterministic locks guard draft inputs, backed by `rpp-wallet locks list|release` and tunable expiry via `wallet.policy.pending_lock_timeout`.【F:docs/wallet_phase2_policies_prover.md†L28-L38】
* **Targeted rescans** – `rpp-wallet rescan --from-height/--lookback-blocks` coordinates focused re-indexing while `wallet.rescan.*` governs automatic sweeps.【F:docs/wallet_phase2_policies_prover.md†L40-L45】
* **Pluggable prover backends** – Configure mock or STWO proofs with `wallet.prover.*` and the crate’s `prover-*` feature flags.【F:docs/wallet_phase2_policies_prover.md†L46-L55】

### Requirements & rollout checklist

* **Configuration:** Update `config/wallet.toml` (or environment-specific overlays) to set the new `wallet.policy`, `wallet.fees`, `wallet.rescan`, and `wallet.prover` keys. See [Wallet Phase 2 Policies & Prover Guide](../../docs/wallet_phase2_policies_prover.md) for detailed defaults and operational guidance.【F:docs/wallet_phase2_policies_prover.md†L1-L71】
* **Runtime restarts:** Changing policy, fee, or prover settings requires restarting the wallet runtime; there is no live reload yet.【F:config/wallet.toml†L1-L55】
* **Operational playbooks:** Extend on-call procedures with the troubleshooting steps for fee underruns, lock conflicts, and prover timeouts outlined in the Phase 2 guide.【F:docs/wallet_phase2_policies_prover.md†L57-L71】

### Feature flags

The crate ships with feature-gated prover integrations. Enable them via `cargo`:

* `prover-mock` (default) – Lightweight mock backend for development and CI.
* `prover-stwo` – STWO backend; requires `wallet.prover.enabled = true` in config to activate at runtime.
* `prover-stwo-simd` – STWO backend with SIMD acceleration; implies `prover-stwo`.

Refer to `Cargo.toml` for the complete flag graph and dependency list.【F:rpp/wallet/Cargo.toml†L7-L23】

### GUI unit tests

The iced wallet UI models and state machines are only compiled when the
`wallet_gui` feature flag is enabled. Run their unit tests explicitly with:

```
cargo test -p rpp-wallet --features wallet_gui
```

The CI `cargo xtask test-unit` entry point also enables `wallet_gui` to cover
these suites.【F:xtask/src/main.rs†L138-L171】
