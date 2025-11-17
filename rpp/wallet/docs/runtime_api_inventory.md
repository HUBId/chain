# Runtime API inventory for wallet decoupling

This inventory enumerates every `use rpp::…` dependency under `rpp/wallet/src` (runtime shim, CLI, RPC) and `rpp/wallet-integration-tests/tests/**`. Each entry lists the file, the line(s) where the import appears, and the concrete items (modules, structs, enums, functions, or constants) that are currently pulled from the monolithic `rpp` crate.

## `rpp/wallet/src`

### `src/runtime.rs`
- L3: `pub use rpp::runtime::*;` — wholesale re-export of the runtime shim (all runtime modules become part of the wallet crate surface whenever the `runtime` feature is enabled).

### `src/cli/wallet.rs`
- L21: `rpp::runtime::config::WalletConfig as RuntimeWalletConfig` — runtime-driven wallet configuration loader.
- L23 (feature `wallet_rpc_mtls`): `rpp::runtime::config::WalletRpcSecurityBinding` — TLS binding details for wallet RPC.
- L24: `rpp::runtime::wallet::rpc::WalletIdentity` — local identity representation for RPC auth.
- L26 (feature `wallet_rpc_mtls`): `rpp::runtime::wallet::rpc::{WalletRbacStore, WalletRole, WalletRoleSet, WalletSecurityBinding, WalletSecurityPaths}` — RBAC models and file-path helpers for authenticated RPC nodes.
- L29: `rpp::runtime::RuntimeMode` — used to resolve default config paths per runtime mode.

### `src/cli/telemetry.rs`
- L7: `rpp::runtime::config::WalletConfig as RuntimeWalletConfig` — used to parse GUI telemetry opt-in flag from the runtime config file.
- L8: `rpp::runtime::RuntimeMode` — used to resolve the default wallet config path for CLI telemetry settings.

### `src/rpc/mod.rs`
- L79 (feature `runtime`): `rpp::runtime::telemetry::metrics::{RuntimeMetrics, WalletAction, WalletActionResult}` — runtime telemetry primitives recorded by the wallet RPC router.
- L1916 (test helpers): `rpp::runtime::telemetry::metrics::RuntimeMetrics` — test fixture uses `RuntimeMetrics::noop()` while instantiating the router.

## `rpp/wallet-integration-tests/tests`

### `rpp/wallet-integration-tests/tests/wallet_workflow_snapshot.rs`
- L16: `rpp::runtime::telemetry::metrics::RuntimeMetrics` — telemetry context passed to wallet runtime fixture.
- L17–L20: `rpp::runtime::wallet::{json_rpc_router, DeterministicSync, WalletRuntime, WalletRuntimeConfig, WalletRuntimeHandle, WalletSecurityPaths}` — wallet runtime orchestration and RPC router wiring imported directly from `rpp`.

### `rpp/wallet-integration-tests/tests/vendor_electrs_tracker_scenario.rs`
- L16: `rpp::errors::{ChainError, ChainResult}` — shared error/result types from core runtime.
- L17–L20: `rpp::proofs::rpp::{encode_transaction_witness, AccountBalanceWitness, TransactionUtxoSnapshot, TransactionWitness, UtxoOutpoint}` — proof serialization helpers needed by the tracker scenario.
- L21: `rpp::runtime::config::NodeConfig` — runtime node configuration wrapper.
- L22: `rpp::runtime::node::Node` — full node handle to spin up a runtime daemon inside the test.
- L23: `rpp::runtime::orchestration::PipelineOrchestrator` — orchestration harness for runtime services.
- L24: `rpp::runtime::sync::{PayloadProvider, ReconstructionRequest, RuntimeRecursiveProofVerifier}` — sync traits/types used to wire runtime adapters.
- L25: `rpp::runtime::types::{BlockPayload, SignedTransaction}` — runtime block/transaction payload models.
- L26: `rpp::runtime::RuntimeMetrics` — telemetry context for runtime adapters.
- L27: `rpp::storage::state::utxo::StoredUtxo` — shared UTXO representation reused in proofs.
- L28: `rpp::zk::rpp_adapter::{compute_public_digest, Digest32, RppStarkHasher}` — STARK helper utilities for digesting proofs.
- L47: `rpp::runtime::types::proofs::RppStarkProof` — proof type for verifying ledger metadata exported from the tracker.

### `rpp/wallet-integration-tests/tests/wallet_electrs_api.rs`
- L21: `rpp::api::{self, ApiContext}` — API surface used to bootstrap wallet-facing HTTP endpoints.
- L22: `rpp::config::NodeConfig` — node configuration loader.
- L23: `rpp::crypto::{load_keypair, sign_message}` — signing helpers for transaction submission tests.
- L24: `rpp::interfaces::WalletHistoryResponse` — runtime API DTO for wallet history responses.
- L25: `rpp::orchestration::PipelineOrchestrator` — runtime orchestrator for node services.
- L26–L29: `rpp::proofs::rpp::{encode_transaction_witness, AccountBalanceWitness, TransactionUtxoSnapshot, TransactionWitness, UtxoOutpoint}` — proof tooling reused by the Electrs API tests.
- L30–L32: `rpp::runtime::config::{FeatureGates as NodeFeatureGates, NetworkLimitsConfig, NetworkTlsConfig}` — runtime node configuration structs needed to wire Electrs against the node.
- L33: `rpp::runtime::node::Node` — runtime daemon handle.
- L34: `rpp::runtime::sync::{PayloadProvider, ReconstructionRequest, RuntimeRecursiveProofVerifier}` — sync traits used by the runtime adapters.
- L35: `rpp::runtime::types::proofs::{ChainProof, RppStarkProof}` — proof bundle types reused for signed transactions.
- L36–L37: `rpp::runtime::types::transaction::{SignedTransaction, Transaction as RuntimeTransaction}` — runtime transaction representations.
- L38: `rpp::runtime::types::TransactionProofBundle` — combined transaction/proof payload structure.
- L39: `rpp::runtime::RuntimeMetrics` (duplicated by L40 but retained in file) — runtime metrics context passed to wallet instantiation.
- L40: `rpp::runtime::{RuntimeMetrics, RuntimeMode}` — duplicate `RuntimeMetrics` import plus `RuntimeMode` for config-path logic.
- L41: `rpp::storage::state::utxo::StoredUtxo` — shared UTXO type used when preparing witnesses.
- L42–L45: `rpp::wallet::config::{CacheConfig, ElectrsConfig, FeatureGates, NetworkSelection as WalletNetworkSelection, P2pConfig, TrackerConfig}` — wallet-specific runtime config definitions accessed through the monorepo `rpp` crate.
- L46: `rpp::wallet::ui::tabs::history::{HistoryEntry, HistoryStatus}` — UI-layer history DTOs leveraged in assertions.
- L47: `rpp::wallet::ui::wallet::{TrackerState, Wallet}` — wallet UI domain types used by the integration test.
- L48–L52: `rpp::wallet::vendor::electrs::{firewood_adapter::RuntimeAdapters, init::initialize, rpp_ledger::bitcoin::blockdata::block::Header, rpp_ledger::bitcoin::{BlockHash, OutPoint, Script, Txid}, rpp_ledger::bitcoin_slices::bsl::Transaction as LedgerTransaction}` — vendor shims imported through the top-level `rpp` crate.
- L53–L58: `rpp::wallet::vendor::electrs::types::{bsl_txid, encode_ledger_memo, encode_ledger_script, encode_transaction_metadata, LedgerMemoPayload, LedgerScriptPayload, RppStarkProofAudit, RppStarkReportSummary, StatusDigest, StoredTransactionMetadata, StoredVrfAudit, VrfInputDescriptor, VrfOutputDescriptor}` — Electrs data models and helpers.
- L59: `rpp::zk::rpp_adapter::{compute_public_digest, Digest32, RppStarkHasher}` — STARK helper utilities.

### `rpp/wallet-integration-tests/tests/vendor_electrs_init.rs`
- L10: `rpp::errors::{ChainError, ChainResult}` — runtime error/result types.
- L11: `rpp::runtime::config::NodeConfig` — runtime node configuration.
- L12: `rpp::runtime::node::Node` — runtime daemon handle.
- L13: `rpp::runtime::orchestration::PipelineOrchestrator` — orchestrator used by Electrs init tests.
- L14: `rpp::runtime::sync::{PayloadProvider, ReconstructionRequest, RuntimeRecursiveProofVerifier}` — sync traits.
- L15: `rpp::runtime::types::BlockPayload` — block payload definition for runtime adapters.
- L16: `rpp::runtime::RuntimeMetrics` — telemetry context passed to runtime adapters.

### `rpp/wallet-integration-tests/tests/vendor_electrs_mempool.rs`
- L5: `rpp::consensus::BftVoteKind` — consensus vote kind enum shared with the runtime.
- L6: `rpp::runtime::config::QueueWeightsConfig` — mempool queue weighting config imported from runtime.
- L7–L10: `rpp::runtime::node::{MempoolStatus, PendingIdentitySummary, PendingTransactionSummary, PendingUptimeSummary, PendingVoteSummary}` — runtime mempool DTOs powering the Electrs mempool adapter tests.

### `tests/vendor_electrs_index.rs`
- L11–L14 (feature `backend-rpp-stark`): `rpp::proofs::rpp::{encode_transaction_witness, AccountBalanceWitness, TransactionUtxoSnapshot, TransactionWitness, UtxoOutpoint}` — proof helpers used by the tracker.
- L16: `rpp::runtime::config::QueueWeightsConfig` — mempool weighting config required by the indexer tests.
- L18: `rpp::runtime::node::{MempoolStatus, PendingTransactionSummary}` — mempool DTOs used while constructing tracker fixtures.
- L20: `rpp::runtime::types::proofs::ChainProof` — proof bundle type.
- L22: `rpp::runtime::types::proofs::RppStarkProof` — STARK proof container.
- L24: `rpp::runtime::types::transaction::Transaction as RuntimeTransaction` — runtime transaction DTO.
- L26: `rpp::runtime::types::SignedTransaction` — signed transaction DTO.
- L28: `rpp::storage::state::utxo::StoredUtxo` — UTXO storage record reused in witnesses.
- L30: `rpp::zk::rpp_adapter::{compute_public_digest, Digest32, RppStarkHasher}` — STARK hashing helpers.

### `tests/vendor_electrs_signals.rs`
- L10: `rpp::runtime::supervisor::Supervisor` — runtime supervisor used to drive simulated signal handling.

## APIs that need to live in `rpp-wallet-interface`

The imports above fall into several runtime-owned domains that the wallet depends upon. To decouple the wallet from the monolithic `rpp` crate, the following API clusters should be moved (or re-exposed) through a dedicated `rpp-wallet-interface` crate:

1. **Wallet runtime orchestration:** `WalletRuntime`, `WalletRuntimeHandle`, `WalletRuntimeConfig`, `WalletSecurityPaths`, `json_rpc_router`, `PipelineOrchestrator`, `RuntimeAdapters`, and the RPC identity/RBAC models. These are needed by both the CLI and integration tests to boot wallet runtimes and authorize RPC.
2. **Runtime configuration surfaces:** `WalletConfig`, `WalletRpcSecurityBinding`, `RuntimeMode`, `NodeConfig`, `FeatureGates`, `NetworkLimitsConfig`, `NetworkTlsConfig`, and `QueueWeightsConfig`. CLI telemetry and Electrs scenarios read these structures directly.
3. **Telemetry primitives:** `RuntimeMetrics`, `WalletAction`, `WalletActionResult`, plus the metric helpers invoked by RPC handlers and tests.
4. **Node and sync DTOs:** `Node`, `Sync` traits (`PayloadProvider`, `ReconstructionRequest`, `RuntimeRecursiveProofVerifier`), `MempoolStatus`, `Pending*Summary` structs, `BlockPayload`, and `TransactionProofBundle`. Electrs components and tests construct these types directly.
5. **Proof and cryptography utilities:** `encode_transaction_witness`, `AccountBalanceWitness`, `TransactionWitness`, `UtxoOutpoint`, `ChainProof`, `RppStarkProof`, `compute_public_digest`, `Digest32`, `RppStarkHasher`, and shared `StoredUtxo` formats. These are required to keep wallet-side trackers in sync with runtime proof formats.
6. **Operational glue:** `Supervisor`, `RuntimeAdapters` and other vendor-specific shims (Electrs adapters, `Tracker`, history UI DTOs, etc.) that currently flow through `rpp::wallet::…` namespaces but originate from the runtime tree.
7. **Core support types:** shared error/result definitions (`ChainError`, `ChainResult`), consensus enums (`BftVoteKind`), API contexts (`ApiContext`, `WalletHistoryResponse`), cryptographic helpers (`load_keypair`, `sign_message`), and orchestration-level interfaces the wallet needs during testing.

Extracting these clusters into `rpp-wallet-interface` will allow the wallet crate (and its tests) to depend only on the stable interface layer rather than on the entire `rpp` runtime tree, unlocking separate compilation and deployment of the wallet without bundling the full node implementation.
