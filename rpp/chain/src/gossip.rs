use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use libp2p::PeerId;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::consensus::SignedBftVote;
use crate::node::NodeHandle;
use crate::proof_system::ProofVerifierRegistry;
use crate::runtime::node_runtime::node::{NodeEvent, ProofReputationCode};
use crate::runtime::sync::RuntimeTransactionProofVerifier;
use crate::types::{Block, TransactionProofBundle};
use parking_lot::Mutex;
use rpp_p2p::{
    GossipTopic, PersistentProofStorage, PipelineError, ProofMempool, ProofRecord,
    RuntimeProofValidator,
};

/// Processes decoded gossip payloads for downstream pipelines.
pub trait GossipProcessor: Send + Sync + 'static {
    /// Handle an incoming block proposal payload.
    fn handle_block(&self, peer: &PeerId, payload: &[u8]) -> Result<()>;

    /// Handle an incoming consensus vote payload.
    fn handle_vote(&self, peer: &PeerId, payload: &[u8]) -> Result<()>;

    /// Handle an incoming proof bundle payload.
    fn handle_proof(&self, peer: &PeerId, payload: &[u8]) -> Result<()>;
}

/// Default gossip processor that forwards payloads into the node runtime.
#[derive(Clone)]
pub struct NodeGossipProcessor {
    node: NodeHandle,
    proofs: Arc<Mutex<ProofMempool>>,
    seen_blocks: Arc<Mutex<HashSet<String>>>,
    seen_votes: Arc<Mutex<HashSet<String>>>,
}

impl NodeGossipProcessor {
    pub fn new(node: NodeHandle, proof_storage_path: impl Into<PathBuf>) -> Self {
        let registry = ProofVerifierRegistry::default();
        let backend = Arc::new(RuntimeTransactionProofVerifier::new(registry));
        let validator = Arc::new(RuntimeProofValidator::new(backend));
        let storage_path = proof_storage_path.into();
        let storage = Arc::new(
            PersistentProofStorage::open(storage_path)
                .expect("persistent proof pipeline must initialise"),
        );
        let recovered = storage.load().unwrap_or_else(|err| {
            warn!(?err, "failed to load persisted proof records");
            Vec::new()
        });
        let proofs = ProofMempool::new(validator, storage)
            .expect("in-memory proof pipeline must initialise");
        let processor = Self {
            node,
            proofs: Arc::new(Mutex::new(proofs)),
            seen_blocks: Arc::new(Mutex::new(HashSet::new())),
            seen_votes: Arc::new(Mutex::new(HashSet::new())),
        };
        processor.rehydrate(recovered);
        processor
    }

    fn rehydrate(&self, records: Vec<ProofRecord>) {
        if records.is_empty() {
            return;
        }
        for record in records {
            match serde_json::from_slice::<TransactionProofBundle>(&record.payload) {
                Ok(bundle) => {
                    if let Err(err) = self.node.submit_transaction(bundle) {
                        warn!(?err, "failed to resubmit cached proof bundle");
                    }
                }
                Err(err) => {
                    warn!(?err, "failed to decode cached proof bundle");
                }
            }
        }
        let mut proofs = self.proofs.lock();
        while proofs.pop().is_some() {}
    }
}

impl GossipProcessor for NodeGossipProcessor {
    fn handle_block(&self, _peer: &PeerId, payload: &[u8]) -> Result<()> {
        let block: Block = serde_json::from_slice(payload)
            .map_err(|err| anyhow!("invalid block gossip payload: {err}"))?;
        {
            let mut guard = self.seen_blocks.lock();
            if !guard.insert(block.hash.clone()) {
                return Ok(());
            }
        }
        self.node
            .submit_block_proposal(block)
            .map(|_| ())
            .map_err(|err| anyhow!("failed to submit block proposal: {err}"))
    }

    fn handle_vote(&self, _peer: &PeerId, payload: &[u8]) -> Result<()> {
        let vote: SignedBftVote = serde_json::from_slice(payload)
            .map_err(|err| anyhow!("invalid vote gossip payload: {err}"))?;
        {
            let mut guard = self.seen_votes.lock();
            if !guard.insert(vote.hash()) {
                return Ok(());
            }
        }
        self.node
            .submit_vote(vote)
            .map(|_| ())
            .map_err(|err| anyhow!("failed to submit vote: {err}"))
    }

    fn handle_proof(&self, peer: &PeerId, payload: &[u8]) -> Result<()> {
        let mut proofs = self.proofs.lock();
        match proofs.ingest(*peer, GossipTopic::WitnessProofs, payload.to_vec()) {
            Ok(_) => {}
            Err(PipelineError::Duplicate) => {
                drop(proofs);
                self.record_proof_penalty(peer, ProofReputationCode::DuplicateProof);
                return Ok(());
            }
            Err(PipelineError::Validation(err)) => {
                drop(proofs);
                self.record_proof_penalty(peer, ProofReputationCode::InvalidProof);
                return Err(anyhow!("failed to ingest proof gossip: {err}"));
            }
            Err(err) => {
                drop(proofs);
                self.record_proof_penalty(peer, ProofReputationCode::PipelineFailure);
                return Err(anyhow!("failed to ingest proof gossip: {err}"));
            }
        }
        drop(proofs);
        let bundle: TransactionProofBundle = serde_json::from_slice(payload)
            .map_err(|err| anyhow!("invalid proof gossip payload: {err}"))?;
        let outcome = self
            .node
            .submit_transaction(bundle)
            .map(|_| ())
            .map_err(|err| anyhow!("failed to submit proof bundle: {err}"));
        let mut proofs = self.proofs.lock();
        while proofs.pop().is_some() {}
        outcome
    }
}

impl NodeGossipProcessor {
    fn record_proof_penalty(&self, peer: &PeerId, code: ProofReputationCode) {
        if let Some(handle) = self.node.p2p_handle() {
            let peer_id = *peer;
            tokio::spawn(async move {
                if let Err(err) = handle.apply_reputation_penalty(peer_id, code).await {
                    warn!(?err, ?peer_id, "failed to apply reputation penalty");
                }
            });
        } else {
            warn!(
                ?peer,
                "p2p runtime handle unavailable for reputation penalty"
            );
        }
    }
}

/// Spawn the node event worker that consumes libp2p events.
pub fn spawn_node_event_worker<P: GossipProcessor>(
    mut events: broadcast::Receiver<NodeEvent>,
    processor: Arc<P>,
    mut shutdown_rx: Option<watch::Receiver<bool>>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            if let Some(rx) = shutdown_rx.as_mut() {
                tokio::select! {
                    result = rx.changed() => {
                        match result {
                            Ok(()) => {
                                if *rx.borrow() {
                                    debug!("node event worker received shutdown signal");
                                    break;
                                }
                            }
                            Err(_) => {
                                debug!("node event worker shutdown channel closed");
                                break;
                            }
                        }
                    }
                    event = events.recv() => {
                        if should_stop(&processor, event).await? {
                            break;
                        }
                    }
                }
            } else {
                let event = events.recv().await;
                if should_stop(&processor, event).await? {
                    break;
                }
            }
        }
        Ok(())
    })
}

async fn should_stop<P: GossipProcessor>(
    processor: &Arc<P>,
    event: Result<NodeEvent, broadcast::error::RecvError>,
) -> Result<bool> {
    match event {
        Ok(NodeEvent::Gossip { peer, topic, data }) => {
            match topic {
                rpp_p2p::GossipTopic::Blocks => {
                    if let Err(err) = processor.handle_block(&peer, &data) {
                        warn!(?peer, ?err, "failed to handle block gossip");
                    }
                }
                rpp_p2p::GossipTopic::Votes => {
                    if let Err(err) = processor.handle_vote(&peer, &data) {
                        warn!(?peer, ?err, "failed to handle vote gossip");
                    }
                }
                rpp_p2p::GossipTopic::WitnessProofs => {
                    if let Err(err) = processor.handle_proof(&peer, &data) {
                        warn!(?peer, ?err, "failed to handle proof gossip");
                    }
                }
                other => {
                    debug!(?peer, ?other, "ignoring unsupported gossip topic");
                }
            }
            Ok(false)
        }
        Ok(_) => Ok(false),
        Err(broadcast::error::RecvError::Closed) => {
            debug!("p2p event stream closed");
            Ok(true)
        }
        Err(broadcast::error::RecvError::Lagged(skipped)) => {
            warn!(skipped, "lagged on gossip event stream");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    use rpp_p2p::GossipTopic;
    use tokio::sync::{broadcast, watch};
    use tokio::time::sleep;

    #[derive(Default)]
    struct TestProcessor {
        events: Mutex<Vec<(GossipTopic, Vec<u8>)>>,
    }

    impl TestProcessor {
        fn record(&self, topic: GossipTopic, payload: &[u8]) {
            self.events.lock().unwrap().push((topic, payload.to_vec()));
        }

        fn topics(&self) -> Vec<GossipTopic> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .map(|(topic, _)| *topic)
                .collect()
        }
    }

    impl GossipProcessor for TestProcessor {
        fn handle_block(&self, _peer: &PeerId, payload: &[u8]) -> Result<()> {
            self.record(GossipTopic::Blocks, payload);
            Ok(())
        }

        fn handle_vote(&self, _peer: &PeerId, payload: &[u8]) -> Result<()> {
            self.record(GossipTopic::Votes, payload);
            Ok(())
        }

        fn handle_proof(&self, _peer: &PeerId, payload: &[u8]) -> Result<()> {
            self.record(GossipTopic::WitnessProofs, payload);
            Ok(())
        }
    }

    #[tokio::test]
    async fn routes_gossip_by_topic() {
        let (tx, rx) = broadcast::channel(8);
        let processor = Arc::new(TestProcessor::default());
        let handle = spawn_node_event_worker(rx, Arc::clone(&processor), None);

        let peer = PeerId::random();
        tx.send(NodeEvent::Gossip {
            peer: peer.clone(),
            topic: GossipTopic::Blocks,
            data: b"block".to_vec(),
        })
        .unwrap();
        tx.send(NodeEvent::Gossip {
            peer: peer.clone(),
            topic: GossipTopic::Votes,
            data: b"vote".to_vec(),
        })
        .unwrap();
        tx.send(NodeEvent::Gossip {
            peer,
            topic: GossipTopic::WitnessProofs,
            data: b"proof".to_vec(),
        })
        .unwrap();

        sleep(Duration::from_millis(50)).await;
        drop(tx);

        handle.await.unwrap().unwrap();

        let topics = processor.topics();
        assert_eq!(topics.len(), 3);
        assert!(topics.contains(&GossipTopic::Blocks));
        assert!(topics.contains(&GossipTopic::Votes));
        assert!(topics.contains(&GossipTopic::WitnessProofs));
    }

    #[tokio::test]
    async fn stops_on_shutdown_signal() {
        let (tx, rx) = broadcast::channel(8);
        let processor = Arc::new(TestProcessor::default());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = spawn_node_event_worker(rx, Arc::clone(&processor), Some(shutdown_rx));

        tx.send(NodeEvent::Gossip {
            peer: PeerId::random(),
            topic: GossipTopic::Blocks,
            data: b"block".to_vec(),
        })
        .unwrap();

        sleep(Duration::from_millis(20)).await;
        shutdown_tx.send(true).unwrap();
        drop(tx);

        handle.await.unwrap().unwrap();
        assert!(!processor.topics().is_empty());
    }
}
