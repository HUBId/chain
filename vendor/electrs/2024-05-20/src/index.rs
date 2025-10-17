use std::path::Path;

use anyhow::Result;

use crate::vendor::electrs::chain::{Chain, NewHeader};
use crate::vendor::electrs::db::{Db, WriteBatch};
use crate::vendor::electrs::rpp_ledger::bitcoin::blockdata::block::Header as BlockHeader;
use crate::vendor::electrs::rpp_ledger::bitcoin::{Network, OutPoint, Script, Txid};
use crate::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction;
use crate::vendor::electrs::types::{
    bsl_txid, HeaderRow, ScriptHash, ScriptHashRow, SerBlock, SpendingPrefixRow, TxidRow,
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

fn serialize_block(transactions: &[Transaction]) -> SerBlock {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(transactions.len() as u32).to_le_bytes());
    for tx in transactions {
        let inputs = tx.inputs();
        buf.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
        for input in inputs {
            buf.extend_from_slice(input.txid.as_bytes());
            buf.extend_from_slice(&input.vout.to_le_bytes());
        }
        let outputs = tx.outputs();
        buf.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
        for output in outputs {
            buf.extend_from_slice(&(output.as_bytes().len() as u32).to_le_bytes());
            buf.extend_from_slice(output.as_bytes());
        }
        let memo = tx.memo();
        buf.extend_from_slice(&(memo.len() as u32).to_le_bytes());
        buf.extend_from_slice(memo);
    }
    buf
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
