#![cfg(feature = "prover-stwo")]

mod fixtures {
    #[path = "common/stwo_transaction.rs"]
    pub mod stwo_transaction;
}

pub(crate) use fixtures::stwo_transaction as fixture;

#[path = "unit/aggregation.rs"]
mod aggregation;
#[path = "unit/circuits.rs"]
mod circuits;
#[path = "unit/helpers.rs"]
mod helpers;
