use std::collections::HashMap;

use crate::vendor::electrs::rpp_ledger::bitcoin::blockdata::{
    block::Header as BlockHeader,
    constants,
};
use crate::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, Network};

pub(crate) struct NewHeader {
    header: BlockHeader,
    hash: BlockHash,
    height: usize,
}

impl NewHeader {
    pub(crate) fn from((header, height): (BlockHeader, usize)) -> Self {
        Self {
            hash: header.block_hash(),
            header,
            height,
        }
    }

    pub(crate) fn height(&self) -> usize {
        self.height
    }

    pub(crate) fn hash(&self) -> BlockHash {
        self.hash
    }
}

pub struct Chain {
    headers: Vec<(BlockHash, BlockHeader)>,
    heights: HashMap<BlockHash, usize>,
}

impl Chain {
    pub fn new(network: Network) -> Self {
        let genesis = constants::genesis_block(network);
        let genesis_hash = genesis.header.block_hash();
        let mut headers = Vec::new();
        headers.push((genesis_hash, genesis.header));
        let mut heights = HashMap::new();
        heights.insert(genesis_hash, 0);
        Self { headers, heights }
    }

    pub(crate) fn drop_last_headers(&mut self, _n: usize) {
        todo!("vendor_electrs: implement drop_last_headers once rpp-ledger provides full headers");
    }

    pub(crate) fn load(&mut self, _headers: impl Iterator<Item = BlockHeader>, _tip: BlockHash) {
        todo!("vendor_electrs: load chain from storage once rpp-ledger is available");
    }

    pub(crate) fn get_block_hash(&self, height: usize) -> Option<BlockHash> {
        self.headers.get(height).map(|(hash, _)| *hash)
    }

    pub(crate) fn get_block_header(&self, height: usize) -> Option<&BlockHeader> {
        self.headers.get(height).map(|(_, header)| header)
    }

    pub(crate) fn get_block_height(&self, blockhash: &BlockHash) -> Option<usize> {
        self.heights.get(blockhash).copied()
    }

    pub(crate) fn update(&mut self, _headers: Vec<NewHeader>) {
        todo!("vendor_electrs: implement chain updates once rpp-ledger is wired up");
    }

    pub(crate) fn tip(&self) -> BlockHash {
        self.headers
            .last()
            .map(|(hash, _)| *hash)
            .unwrap_or_default()
    }

    pub(crate) fn height(&self) -> usize {
        self.headers.len().saturating_sub(1)
    }

    pub(crate) fn locator(&self) -> Vec<BlockHash> {
        todo!("vendor_electrs: compute block locator once rpp-ledger headers are available");
    }
}

#[cfg(test)]
mod tests {
    // TODO: Reaktivieren, sobald echte rpp-ledger Header verfügbar sind.
}
