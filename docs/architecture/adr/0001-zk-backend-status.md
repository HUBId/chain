# ADR 0001: ZK Backend Status and Experimental Plonky3 Guard

## Status

Accepted (2025-09-08)

## Context

The STWO prover/verifier stack is production-ready and ships real zero-knowledge
proofs. The Plonky3 modules, on the other hand, currently expose a deterministic
hash stub (`plonky3_backend`) so wallet and node plumbing can be developed in
parallel.【F:prover/plonky3_backend/src/lib.rs†L1-L112】 Prior documentation
implied that the Plonky3 backend generated real proofs, which risks operators
enabling the feature under a false sense of security.

## Decision

Plonky3 remains an **experimental** backend with no cryptographic soundness. A
global guard (`experimental::require_acknowledgement`) prevents constructing the
Plonky3 prover or verifier unless the caller explicitly opts in via the CLI
flag `--experimental-plonky3` or the environment variable
`CHAIN_PLONKY3_EXPERIMENTAL`.【F:rpp/proofs/plonky3/experimental.rs†L1-L76】【F:rpp/proofs/plonky3/prover/mod.rs†L103-L116】【F:rpp/proofs/plonky3/verifier/mod.rs†L105-L118】

When the guard is satisfied, the runtime emits a warning banner and propagates
it through `/status/node`, validator telemetry, and the UI so downstream tooling
cannot mistake the backend for production-grade cryptography.【F:rpp/runtime/node.rs†L140-L188】【F:rpp/runtime/node.rs†L4719-L4741】【F:docs/interfaces/rpc/examples/validator_status_response.json†L1-L120】【F:validator-ui/src/types.ts†L156-L175】

CI and developer scripts set `CHAIN_PLONKY3_EXPERIMENTAL=1` when executing the
Plonky3 suites, keeping the tests runnable while documenting the lack of real
proofs.【F:scripts/test.sh†L195-L205】【F:scripts/build.sh†L161-L170】

## Consequences

* Operators must acknowledge the experimental mode before Plonky3 code paths
  are usable. Automated tooling will exit with a configuration error instead of
  silently generating insecure artifacts.
* API clients and dashboards receive an explicit warning and can block or
  annotate Plonky3 artifacts accordingly.
* Integration tests continue to run against the deterministic stub but now
  mirror the production opt-in behaviour, preventing accidental dependencies on
  the mock backend.

## Follow-up

* Replace the stub with the real Plonky3 prover/verifier stack and retire the
  experimental guard once cryptographic proofs are available.
* Extend CI to report prove/verify runtimes, memory use, and artifact sizes when
  a real backend lands.
* Update operator guides again when the backend transitions from experimental to
  supported.
