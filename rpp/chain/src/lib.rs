//! Core crate wiring together the RPP blockchain runtime.
//!
//! The crate re-exports modules that live in the `rpp` workspace so that
//! consumers can interact with the system through a single entry point. The
//! `runtime`, `consensus`, and `node` modules compose the node lifecycle, while
//! `storage` and `ledger` encapsulate persistent state management. Proof system
//! integrations are exposed under `proof_system`, `stwo`, and `plonky3`, and
//! wallet/UI integrations live in `wallet`.
//!
//! Applications typically depend on [`config::NodeConfig`] to bootstrap a node,
//! [`node::Node`] and [`node::NodeHandle`] to operate it, and the supporting modules for consensus,
//! networking, proofs, and state synchronization.

#[cfg(all(feature = "prover-stwo", feature = "prover-mock"))]
compile_error!("features `prover-stwo` and `prover-mock` are mutually exclusive");
#[path = "../../rpc/api.rs"]
pub mod api;
#[path = "../../proofs/blueprint/mod.rs"]
pub mod blueprint;
#[path = "../../runtime/config.rs"]
pub mod config;
#[path = "../../consensus/node.rs"]
pub mod consensus;
#[path = "../../crypto/mod.rs"]
pub mod crypto;
#[path = "../../runtime/errors.rs"]
pub mod errors;
#[path = "gossip.rs"]
pub mod gossip;
pub use rpp_identity_tree as identity_tree;
#[path = "../../rpc/interfaces.rs"]
pub mod interfaces;
#[path = "../../storage/ledger.rs"]
pub mod ledger;
#[path = "../../storage/migration.rs"]
pub mod migration;
#[path = "../../runtime/node.rs"]
pub mod node;
#[path = "../../runtime/orchestration.rs"]
pub mod orchestration;
#[cfg(feature = "backend-plonky3")]
#[path = "../../proofs/plonky3/mod.rs"]
pub mod plonky3;
pub use prover_backend_interface as proof_backend;
#[path = "../../proofs/proof_system/mod.rs"]
pub mod proof_system;
#[path = "../../reputation/mod.rs"]
pub mod reputation;
#[path = "../../proofs/rpp.rs"]
pub mod rpp;
#[path = "../../runtime/mod.rs"]
pub mod runtime;
#[path = "../../storage/state/mod.rs"]
pub mod state;
#[path = "../../storage/mod.rs"]
pub mod storage;
#[path = "../../proofs/stwo/mod.rs"]
pub mod stwo;
#[cfg(feature = "backend-rpp-stark")]
pub mod zk;
#[path = "../../runtime/sync.rs"]
pub mod sync;
#[path = "../../runtime/types/mod.rs"]
pub mod types;
pub use rpp_crypto_vrf as vrf;
#[path = "../../wallet/ui/mod.rs"]
pub mod wallet;

pub use rpp_consensus as consensus_engine;
