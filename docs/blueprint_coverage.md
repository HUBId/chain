# STWO/Plonky3 Blueprint Coverage Assessment

This document cross-references the blueprint requirements with the current code
base to confirm implementation completeness.

## Motivation & Backend Abstraction

* The architecture enumerates STWO and Plonky3 proof systems and threads the
  selection through the recursive proof descriptor so additional backends can be
  enabled without changing the block model.【F:src/rpp.rs†L43-L158】【F:src/types/block.rs†L132-L142】
* Runtime components exchange proofs through the unified `ChainProof` wrapper,
  which records the originating backend and exposes conversion helpers for STWO
  artifacts.【F:src/types/proofs.rs†L11-L52】
* The proof registry instantiates verifier instances for every backend and
dispatches verification through the shared traits used by wallets and nodes, so
  block validation logic remains backend-agnostic.【F:src/proof_system/mod.rs†L1-L220】

## Wallet (Prover) Responsibilities

* `WalletProver` derives witnesses for identity genesis, transactions, state
  transitions, pruning, uptime, and consensus proofs from local storage and
  converts them into STARK proofs that satisfy the unified prover trait.【F:src/stwo/prover/mod.rs†L42-L448】
* Recursive witnesses fold previous commitments together with state roots from
  `StateCommitmentSnapshot`, ensuring block proofs embed the entire historical
  chain before being broadcast.【F:src/stwo/prover/mod.rs†L210-L257】【F:src/stwo/aggregation/mod.rs†L10-L206】

## Node (Verifier) Responsibilities

* `NodeVerifier` replays every circuit—transaction, identity, state, pruning,
  uptime, consensus, and recursive—to check commitments, traces, and FRI proofs
  deterministically.【F:src/stwo/verifier/mod.rs†L1-L247】
* The node routes proof verification through the shared registry before adding
  artifacts to mempools or importing blocks, enforcing consistency across all
  proof categories.【F:src/proof_system/mod.rs†L90-L220】【F:src/node.rs†L591-L727】

## VRF Poseidon Domain & Key Management

* `PoseidonVrfInput` encodes the `(last_block_header, epoch, tier_seed)` tuple,
  derives Poseidon digests, and exposes fixed-width randomness helpers to match
  the blueprint domain separation requirements.【F:src/vrf/mod.rs†L16-L102】
* `generate_vrf` and `verify_vrf` wrap ed25519 signatures over Poseidon digests,
  hashing proofs into randomness and validating outputs alongside strict proof
  parsing for consensus use.【F:src/vrf/mod.rs†L103-L208】
* `select_validators` derives per-epoch thresholds from the epoch number,
  tier seed, and configurable validator target, blending smoothed binomial
  expectations with the observed randomness quantile so the committee size
  adapts to participation instead of the legacy selection window heuristic.【F:src/vrf/mod.rs†L320-L480】
* Dedicated VRF key lifecycle helpers cover generation, persistence,
  re-loading, and hex conversion so operators and integration tests share the
  same storage format.【F:src/crypto.rs†L17-L229】
* Validator selection emits audit records that the ledger persists per epoch,
  deduplicating proofs and exposing query hooks so historical VRF decisions can
  be inspected alongside consensus data.【F:src/vrf/mod.rs†L360-L494】【F:src/ledger.rs†L100-L214】【F:src/node.rs†L1140-L1214】
* Node status and telemetry snapshots include VRF selection metrics covering the
  submission pool size, accepted validator count, rejections, and fallback
  usage so operators can monitor participation over time.【F:src/node.rs†L57-L125】【F:src/node.rs†L815-L836】【F:src/node.rs†L489-L548】

## Circuit Palette

* **Transaction Circuit** – enforces signature validity, balance conservation,
  nonce progression, and reputation tier requirements before exposing public
  inputs for the STARK prover.【F:src/stwo/circuit/transaction.rs†L1-L200】
* **Identity Genesis Circuit** – binds public keys, wallet addresses, VRF tags,
  and Merkle proofs while ensuring zero initial reputation and vacant tree
  slots.【F:src/stwo/circuit/identity.rs†L1-L200】
* **Uptime Circuit (Timetoke)** – validates window progression, node clock
  bounds, head hash format, and Blake2s commitment parity for availability
  claims.【F:src/stwo/circuit/uptime.rs†L1-L120】
* **Consensus Circuit (BFT)** – aggregates vote weights across rounds, prevents
  duplicates, and enforces quorum thresholds for block proposals.【F:src/stwo/circuit/consensus.rs†L1-L172】
* **Recursive Block Circuit** – folds activity commitments, ledger roots, and
  pruning data into a Poseidon hash that must match the witnessed aggregate,
  guaranteeing each block proves the entire prefix.【F:src/stwo/circuit/recursive.rs†L1-L186】

## Recursive Proof Structure

* `RecursiveAggregator` concatenates identity, transaction, uptime, consensus,
  and state commitments alongside pruning proofs and the prior aggregate to
  compute the next recursive digest, mirroring the circuit constraints.【F:src/stwo/aggregation/mod.rs†L84-L206】
* Block headers persist the ledger roots required by the recursive circuit so
  verifiers can rebuild the same state digest when checking bundles.【F:src/types/block.rs†L35-L99】

## Conclusion

Every role and circuit described in the blueprint is present in the codebase,
end-to-end recursive aggregation matches the specified structure, and the
Plonky3 backend hooks are in place behind the shared abstractions. The blueprint
is therefore fully implemented.
