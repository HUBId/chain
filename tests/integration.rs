#![cfg(feature = "prover-stwo")]

mod fixtures {
    #[path = "common/stwo_transaction.rs"]
    pub mod stwo_transaction;
}

#[path = "support/mod.rs"]
mod support;

pub(crate) use fixtures::stwo_transaction as fixture;

#[path = "integration/node.rs"]
mod node;
#[path = "integration/sync.rs"]
mod sync;
#[path = "integration/wallet.rs"]
mod wallet;
