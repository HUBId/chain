#![no_main]

use libfuzzer_sys::fuzz_target;
use rpp_chain::rpp::ModuleWitnessBundle;
use rpp_chain::types::{
    Block, BlockHeader, BlockProofBundle, ChainProof, PruningProof, ProofSystem, RecursiveProof,
};
use rpp_consensus::ConsensusCertificate;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PruningInput {
    proof: PruningProof,
    header: BlockHeader,
    #[serde(default)]
    previous: Option<PreviousBlock>,
}

#[derive(Debug, Deserialize)]
struct PreviousBlock {
    hash: String,
    header: BlockHeader,
}

impl PreviousBlock {
    fn into_block(self) -> Block {
        let header = self.header;
        Block {
            hash: self.hash,
            header: header.clone(),
            identities: Vec::new(),
            transactions: Vec::new(),
            uptime_proofs: Vec::new(),
            timetoke_updates: Vec::new(),
            reputation_updates: Vec::new(),
            bft_votes: Vec::new(),
            module_witnesses: ModuleWitnessBundle::default(),
            proof_artifacts: Vec::new(),
            pruning_proof: PruningProof::genesis(&header.state_root),
            recursive_proof: placeholder_recursive_proof(),
            stark: BlockProofBundle {
                transaction_proofs: Vec::new(),
                state_proof: default_chain_proof(),
                pruning_proof: default_chain_proof(),
                recursive_proof: default_chain_proof(),
            },
            signature: String::new(),
            consensus: ConsensusCertificate::genesis(),
            consensus_proof: None,
            pruned: false,
        }
    }
}

fn default_chain_proof() -> ChainProof {
    ChainProof::Stwo(Default::default())
}

fn placeholder_recursive_proof() -> RecursiveProof {
    RecursiveProof {
        system: ProofSystem::Stwo,
        commitment: RecursiveProof::anchor(),
        previous_commitment: Some(RecursiveProof::anchor()),
        proof: default_chain_proof(),
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = serde_json::from_slice::<PruningInput>(data) {
        let previous_block = input.previous.map(PreviousBlock::into_block);
        let previous_ref = previous_block.as_ref();
        let _ = input.proof.verify(previous_ref, &input.header);
    }
});
