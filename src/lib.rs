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
#[path = "../rpp/rpc/api.rs"]
pub mod api;
#[path = "../rpp/proofs/blueprint/mod.rs"]
pub mod blueprint;
#[path = "../rpp/runtime/config.rs"]
pub mod config;
#[path = "../rpp/consensus/node.rs"]
pub mod consensus;
#[path = "../rpp/crypto/mod.rs"]
pub mod crypto;
#[path = "../rpp/runtime/errors.rs"]
pub mod errors;
#[path = "gossip.rs"]
pub mod gossip;
#[path = "../rpp/storage/identity_tree.rs"]
pub mod identity_tree;
#[path = "../rpp/rpc/interfaces.rs"]
pub mod interfaces;
#[path = "../rpp/storage/ledger.rs"]
pub mod ledger;
#[path = "../rpp/storage/migration.rs"]
pub mod migration;
#[path = "../rpp/runtime/node.rs"]
pub mod node;
#[path = "../rpp/runtime/orchestration.rs"]
pub mod orchestration;
#[cfg(feature = "backend-plonky3")]
#[path = "../rpp/proofs/plonky3/mod.rs"]
pub mod plonky3;
pub use prover_backend_interface as proof_backend;
#[path = "../rpp/proofs/proof_system/mod.rs"]
pub mod proof_system;
#[path = "../rpp/reputation/mod.rs"]
pub mod reputation;
#[path = "../rpp/proofs/rpp.rs"]
pub mod rpp;
#[path = "../rpp/runtime/mod.rs"]
pub mod runtime;
#[path = "../rpp/storage/state/mod.rs"]
pub mod state;
#[path = "../rpp/storage/mod.rs"]
pub mod storage;
#[path = "../rpp/proofs/stwo/mod.rs"]
pub mod stwo;
#[cfg(feature = "backend-rpp-stark")]
pub mod zk;
#[path = "../rpp/runtime/sync.rs"]
pub mod sync;
#[path = "../rpp/runtime/types/mod.rs"]
pub mod types;
#[path = "../rpp/crypto/vrf/mod.rs"]
pub mod vrf;
#[path = "../rpp/wallet/ui/mod.rs"]
pub mod wallet;

pub use rpp_consensus as consensus_engine;
