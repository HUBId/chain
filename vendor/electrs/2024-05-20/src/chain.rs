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

    pub(crate) fn drop_last_headers(&mut self, n: usize) {
        for _ in 0..n {
            if let Some((hash, _)) = self.headers.pop() {
                self.heights.remove(&hash);
            }
        }
    }

    pub(crate) fn load(&mut self, headers: impl Iterator<Item = BlockHeader>, tip: BlockHash) {
        self.headers.clear();
        self.heights.clear();

        for (height, header) in headers.enumerate() {
            let hash = header.block_hash();
            self.heights.insert(hash, height);
            self.headers.push((hash, header));
        }

        if self.tip() != tip {
            self.headers
                .iter()
                .position(|(hash, _)| *hash == tip)
                .map(|index| {
                    let retain = index + 1;
                    self.headers.truncate(retain);
                    self.heights
                        .retain(|hash, height| *height < retain && *hash == self.headers[*height].0);
                })
                .unwrap_or_default();
        }
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

    pub(crate) fn update(&mut self, headers: Vec<NewHeader>) {
        for header in headers {
            let hash = header.hash();
            let height = header.height();

            if let Some(existing_height) = self.heights.get(&hash) {
                if *existing_height <= height {
                    continue;
                }
            }

            if height > self.headers.len() {
                continue;
            }

            if height == self.headers.len() {
                self.headers.push((hash, header.header.clone()));
            } else {
                self.headers[height] = (hash, header.header.clone());
                self.headers.truncate(height + 1);
            }

            self.heights.insert(hash, height);
        }
    }

    pub fn tip(&self) -> BlockHash {
        self.headers
            .last()
            .map(|(hash, _)| *hash)
            .unwrap_or_default()
    }

    pub fn height(&self) -> usize {
        self.headers.len().saturating_sub(1)
    }

    pub fn locator(&self) -> Vec<BlockHash> {
        if self.headers.is_empty() {
            return Vec::new();
        }

        let mut locator = Vec::new();
        let mut step = 1usize;
        let mut height = self.height();

        while let Some(hash) = self.get_block_hash(height) {
            locator.push(hash);
            if locator.len() >= 10 {
                step *= 2;
            }
            if height < step {
                break;
            }
            height -= step;
        }

        if let Some(genesis) = self.get_block_hash(0) {
            if locator.last() != Some(&genesis) {
                locator.push(genesis);
            }
        }

        locator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_tracks_headers() {
        let mut chain = Chain::new(Network::Regtest);
        let genesis = chain.tip();
        assert_eq!(chain.height(), 0);

        let mut header = constants::genesis_block(Network::Regtest).header;
        header.timestamp = 1;
        header.parent = genesis;
        let new_header = NewHeader::from((header.clone(), 1));
        chain.update(vec![new_header]);

        assert_eq!(chain.height(), 1);
        assert_eq!(chain.tip(), header.block_hash());

        chain.drop_last_headers(1);
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.tip(), genesis);
    }
}
