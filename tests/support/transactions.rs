use rpp_chain::proofs::rpp::TransactionWitness;
use rpp_chain::runtime::types::block::Block;
use rpp_chain::runtime::types::proofs::ChainProof;
use rpp_chain::runtime::types::transaction::SignedTransaction;

/// Clone the transaction/proof/witness triple at `index` so tests can replay the
/// exact same spend twice.
///
/// The cloned [`SignedTransaction`] still references the original inputs while
/// the accompanying [`TransactionWitness`] preserves the previously gathered
/// input/output snapshots. Keeping both artefacts in lockstep allows callers to
/// inject a byte-for-byte identical spend a second time, which is the minimal
/// setup required to trigger double-spend handling without having to rebuild the
/// surrounding proof objects from scratch.
pub fn duplicate_transaction_for_double_spend(
    block: &Block,
    index: usize,
) -> Option<(SignedTransaction, ChainProof, TransactionWitness)> {
    let tx = block.transactions.get(index)?.clone();
    let proof = block.stark.transaction_proofs.get(index)?.clone();
    let witness = block.module_witnesses.transactions.get(index)?.clone();
    Some((tx, proof, witness))
}
