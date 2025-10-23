use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::errors::ChainResult;
use crate::types::{Address, ChainProof, SignedTransaction, UptimeProof};

use super::wallet::Wallet;

#[derive(Clone, Debug, Serialize)]
pub struct TxProof {
    pub wallet_address: Address,
    pub tx_hash: String,
    pub proof: ChainProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_commitment: Option<String>,
}

#[derive(Clone)]
pub struct ProofGenerator {
    wallet: Arc<Wallet>,
}

impl ProofGenerator {
    pub fn new(wallet: Arc<Wallet>) -> Self {
        Self { wallet }
    }

    pub fn generate_tx_proof(&self, tx: &SignedTransaction) -> ChainResult<TxProof> {
        let bundle = self.wallet.prove_transaction(tx)?;
        let proof = bundle.proof;
        let proof_commitment = match &proof {
            ChainProof::Stwo(stark) => Some(stark.commitment.clone()),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(value) => value
                .get("commitment")
                .and_then(|field| field.as_str())
                .map(|field| field.to_owned()),
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => None,
        };

        Ok(TxProof {
            wallet_address: self.wallet.address().clone(),
            tx_hash: hex::encode(tx.hash()),
            proof,
            proof_commitment,
        })
    }

    pub fn generate_uptime_proof(&self) -> ChainResult<UptimeProof> {
        self.wallet.generate_uptime_proof()
    }
}

#[cfg(all(test, feature = "prover-stwo"))]
mod tests {
    use super::*;

    use std::sync::Arc;

    use ed25519_dalek::Keypair;
    use rand::{rngs::StdRng, SeedableRng};
    use tempfile::tempdir;

    use crate::proof_system::ProofVerifierRegistry;
    use crate::proofs::stwo::tests::official_integration::{
        populate_wallet_state, recorded_transaction_proof,
    };
    use crate::storage::Storage;

    #[test]
    fn generate_tx_proof_uses_wallet_pipeline() {
        let fixture = recorded_transaction_proof();

        let temp_dir = tempdir().expect("temporary directory");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        populate_wallet_state(&storage, &fixture.signed_transaction);

        let mut rng = StdRng::from_seed([0x42; 32]);
        let keypair = Keypair::generate(&mut rng);
        let wallet = Arc::new(Wallet::new(storage, keypair));
        let generator = ProofGenerator::new(wallet);

        let proof = generator
            .generate_tx_proof(&fixture.signed_transaction)
            .expect("generate transaction proof");

        assert_eq!(
            proof.tx_hash,
            hex::encode(fixture.signed_transaction.hash()),
            "transaction hash should match",
        );
        if let ChainProof::Stwo(expected) = &fixture.proof {
            assert_eq!(
                proof.proof_commitment.as_deref(),
                Some(expected.commitment.as_str()),
                "commitment should surface from prover",
            );
        }

        let registry = ProofVerifierRegistry::default();
        registry
            .verify_transaction(&proof.proof)
            .expect("proof should verify");
    }

    #[test]
    fn generate_uptime_proof_surfaces_wallet_artifact() {
        let temp_dir = tempdir().expect("temporary directory");
        let storage = Storage::open(temp_dir.path()).expect("open storage");

        let mut rng = StdRng::from_seed([0x24; 32]);
        let keypair = Keypair::generate(&mut rng);
        let address = crate::crypto::address_from_public_key(&keypair.public);

        let mut account =
            crate::types::Account::new(address.clone(), 0, crate::types::Stake::default());
        account.reputation.bind_genesis_identity("genesis-proof");
        storage.persist_account(&account).expect("persist account");

        let wallet = Arc::new(Wallet::new(storage, keypair));
        let generator = ProofGenerator::new(wallet);

        let proof = generator
            .generate_uptime_proof()
            .expect("generate uptime proof");

        let registry = ProofVerifierRegistry::default();
        let zk_proof = proof.proof().expect("embedded zk proof");
        registry
            .verify_uptime(zk_proof)
            .expect("uptime proof should verify");
        assert_eq!(proof.wallet_address, address);
    }
}
