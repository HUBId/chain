use std::path::Path;

use anyhow::{anyhow, Context, Result};

use crate::vendor::electrs::chain::{Chain, NewHeader};
use crate::vendor::electrs::db::{Db, WriteBatch};
use crate::vendor::electrs::rpp_ledger::bitcoin::blockdata::block::Header as BlockHeader;
use crate::vendor::electrs::rpp_ledger::bitcoin::{Network, OutPoint, Script, Txid};
use crate::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction;
use crate::vendor::electrs::types::{
    bsl_txid, deserialize_block, serialize_block, HeaderRow, ScriptHash, ScriptHashRow,
    SpendingPrefixRow, TxidRow,
};

pub struct Index {
    db: Db,
    chain: Chain,
}

impl Index {
    pub fn open(path: impl AsRef<Path>, network: Network) -> Result<Self> {
        let db = Db::open(path.as_ref())?;
        let mut chain = Chain::new(network);
        let stored_headers = db.load_headers()?;
        for (height, header) in stored_headers {
            if height == 0 {
                continue;
            }
            chain.update(vec![NewHeader::from((header, height))]);
        }
        Ok(Self { db, chain })
    }

    pub fn index_block(&mut self, header: BlockHeader, transactions: &[Transaction]) -> Result<()> {
        let height = self.chain.height() + 1;
        let mut batch = WriteBatch::default();

        let header_row = HeaderRow::new(header.clone());
        batch.put_header(height, &header_row);
        let block_bytes = serialize_block(transactions);
        batch.put_block(height, &block_bytes);

        for tx in transactions {
            self.index_transaction(&mut batch, tx, height);
        }

        batch.set_tip(height, header.block_hash());
        self.db.write(batch)?;
        self.chain.update(vec![NewHeader::from((header, height))]);
        Ok(())
    }

    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    pub fn script_history(&self, script: &Script) -> Vec<(usize, Txid)> {
        let scripthash = ScriptHash::new(script);
        let prefix = ScriptHashRow::scan_prefix(scripthash.clone());
        self.db
            .scan_scripthash(prefix)
            .into_iter()
            .map(|(row, txid)| (row.height(), txid))
            .collect()
    }

    pub fn transaction_at(&self, height: usize, txid: Txid) -> Result<Option<Transaction>> {
        let Some(bytes) = self.db.get_block(height) else {
            return Ok(None);
        };
        let transactions = deserialize_block(&bytes)
            .with_context(|| anyhow!("deserialize block at height {height}"))?;
        for tx in transactions {
            if bsl_txid(&tx) == txid {
                return Ok(Some(tx));
            }
        }
        Ok(None)
    }

    pub fn spends_for_outpoint(&self, outpoint: OutPoint) -> Vec<(usize, Txid)> {
        let prefix = SpendingPrefixRow::scan_prefix(outpoint);
        self.db
            .scan_spending(prefix)
            .into_iter()
            .map(|(row, txid)| (row.height(), txid))
            .collect()
    }

    fn index_transaction(&self, batch: &mut WriteBatch, tx: &Transaction, height: usize) {
        let txid = bsl_txid(tx);
        let tx_row = TxidRow::row(txid, height);
        batch.put_txid(tx_row, txid);

        for (output_index, script) in tx.outputs().iter().enumerate() {
            let scripthash = ScriptHash::new(script);
            let row = ScriptHashRow::row(scripthash, height);
            batch.put_script(row, txid);

            // Also link the newly created outpoint for spending lookups.
            let outpoint = OutPoint::new(txid, output_index as u32);
            let spend_row = SpendingPrefixRow::row(outpoint, height);
            batch.put_spending(spend_row, txid);
        }

        for input in tx.inputs() {
            let row = SpendingPrefixRow::row(*input, height);
            batch.put_spending(row, txid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_block_layout() {
        let script = Script::new(vec![1, 2, 3]);
        let tx = Transaction::new(vec![], vec![script], vec![42]);
        let block = serialize_block(&[tx]);
        assert!(!block.is_empty());
    }
}
