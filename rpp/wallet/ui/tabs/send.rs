use serde::Serialize;

use crate::types::Address;

#[derive(Clone, Debug, Serialize)]
pub struct SendPreview {
    pub from: Address,
    pub to: Address,
    pub amount: u128,
    pub fee: u64,
    pub memo: Option<String>,
    pub nonce: u64,
    pub balance_before: u128,
    pub balance_after: u128,
}

impl SendPreview {
    pub fn total(&self) -> u128 {
        self.amount + self.fee as u128
    }
}
