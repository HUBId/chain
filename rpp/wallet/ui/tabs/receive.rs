use serde::Serialize;

use crate::types::Address;

#[derive(Clone, Debug, Serialize)]
pub struct ReceiveTabAddress {
    pub derivation_index: u32,
    pub address: Address,
}

impl ReceiveTabAddress {
    pub fn qr_uri(&self) -> String {
        format!("rpp:{}?index={}", self.address, self.derivation_index)
    }
}
