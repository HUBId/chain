use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use rand::rngs::OsRng;
use rpp_p2p::vendor::PeerId;
use rpp_p2p::{
    handshake::HandshakePayload, Network, NetworkBlockMetadata, NetworkEvent,
    NetworkGlobalStateCommitments, NetworkLightClientUpdate, NetworkPayloadExpectations,
    NetworkPruningCommitment, NetworkPruningEnvelope, NetworkPruningSegment,
    NetworkPruningSnapshot, NetworkReconstructionRequest, NetworkSnapshotSummary,
    NetworkStateSyncChunk, NetworkStateSyncPlan, NetworkTaggedDigestHex, NodeIdentity, Peerstore,
    PeerstoreConfig, PipelineError, ReputationHeuristics, SnapshotChunk, SnapshotItemKind,
    SnapshotResumeState, SnapshotSessionId, SnapshotStore, TierLevel, VRF_HANDSHAKE_CONTEXT,
};
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
use tempfile::{tempdir, TempDir};
use tokio::time::timeout;

fn template_handshake(zsi: &str, tier: TierLevel) -> HandshakePayload {
    let mut rng = OsRng;
    let secret = MiniSecretKey::generate_with(&mut rng);
    let keypair = secret.expand_to_keypair(ExpansionMode::Uniform);
    let public = keypair.public.to_bytes().to_vec();
    let template = HandshakePayload::new(zsi.to_string(), Some(public.clone()), None, tier);
    let proof = keypair
        .sign_simple(VRF_HANDSHAKE_CONTEXT, &template.vrf_message())
        .to_bytes()
        .to_vec();
    HandshakePayload::new(zsi.to_string(), Some(public), Some(proof), tier)
}

fn init_network(
    dir: &TempDir,
    name: &str,
    tier: TierLevel,
    provider: Option<Arc<MockSnapshotProvider>>,
) -> Network {
    let key_path = dir.path().join(format!("{name}.key"));
    let identity = Arc::new(NodeIdentity::load_or_generate(&key_path).expect("identity"));
    let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
    let handshake = template_handshake(name, tier);
    Network::new(
        identity,
        peerstore,
        handshake,
        None,
        1_024,
        1_024,
        ReputationHeuristics::default(),
        provider.map(|p| p as Arc<_>),
    )
    .expect("network")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProviderCall {
    FetchPlan,
    FetchChunk(u64),
    FetchUpdate(u64),
    Resume(u64, u64),
    Ack(SnapshotItemKind, u64),
}

#[derive(Debug)]
struct GateState {
    resume_allowed: bool,
}

#[derive(Debug)]
struct MockSnapshotProvider {
    plan: NetworkStateSyncPlan,
    store: SnapshotStore,
    root: blake3::Hash,
    updates: Vec<NetworkLightClientUpdate>,
    flow: Mutex<Vec<ProviderCall>>,
    resumes: Mutex<Vec<(SnapshotSessionId, u64, u64)>>,
    acknowledgements: Mutex<Vec<(SnapshotSessionId, SnapshotItemKind, u64)>>,
    gate: Mutex<GateState>,
    condvar: Condvar,
    pause_after_chunk: u64,
    last_chunk_index: Mutex<Option<u64>>,
    last_update_index: Mutex<Option<u64>>,
    confirmed_chunk_index: Mutex<Option<u64>>,
    confirmed_update_index: Mutex<Option<u64>>,
    total_chunks: u64,
    total_updates: u64,
}

impl MockSnapshotProvider {
    fn new(plan: NetworkStateSyncPlan, store: SnapshotStore, root: blake3::Hash) -> Arc<Self> {
        let updates = plan.light_client_updates.clone();
        let total_chunks = plan.chunks.len() as u64;
        let total_updates = updates.len() as u64;
        Arc::new(Self {
            plan,
            store,
            root,
            updates,
            flow: Mutex::new(Vec::new()),
            resumes: Mutex::new(Vec::new()),
            acknowledgements: Mutex::new(Vec::new()),
            gate: Mutex::new(GateState {
                resume_allowed: false,
            }),
            condvar: Condvar::new(),
            pause_after_chunk: 1,
            last_chunk_index: Mutex::new(None),
            last_update_index: Mutex::new(None),
            confirmed_chunk_index: Mutex::new(None),
            confirmed_update_index: Mutex::new(None),
            total_chunks,
            total_updates,
        })
    }

    fn flow_log(&self) -> Vec<ProviderCall> {
        self.flow.lock().expect("flow log").clone()
    }

    fn resume_calls(&self) -> Vec<(SnapshotSessionId, u64, u64)> {
        self.resumes.lock().expect("resumes").clone()
    }

    fn acknowledgements(&self) -> Vec<(SnapshotSessionId, SnapshotItemKind, u64)> {
        self.acknowledgements.lock().expect("acks").clone()
    }
}

impl rpp_p2p::SnapshotProvider for MockSnapshotProvider {
    type Error = PipelineError;

    fn open_session(
        &self,
        _session_id: SnapshotSessionId,
        _peer: &PeerId,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn fetch_plan(
        &self,
        _session_id: SnapshotSessionId,
    ) -> Result<NetworkStateSyncPlan, Self::Error> {
        self.flow
            .lock()
            .expect("flow log")
            .push(ProviderCall::FetchPlan);
        Ok(self.plan.clone())
    }

    fn fetch_chunk(
        &self,
        _session_id: SnapshotSessionId,
        chunk_index: u64,
    ) -> Result<SnapshotChunk, Self::Error> {
        if chunk_index >= self.pause_after_chunk {
            let mut state = self.gate.lock().expect("gate");
            while !state.resume_allowed {
                state = self.condvar.wait(state).expect("resume signal");
            }
        }
        let chunk = self.store.chunk(&self.root, chunk_index)?;
        self.flow
            .lock()
            .expect("flow log")
            .push(ProviderCall::FetchChunk(chunk_index));
        {
            let mut last = self.last_chunk_index.lock().expect("last chunk");
            *last = Some(chunk_index);
        }
        Ok(chunk)
    }

    fn fetch_update(
        &self,
        _session_id: SnapshotSessionId,
        update_index: u64,
    ) -> Result<NetworkLightClientUpdate, Self::Error> {
        let mut state = self.gate.lock().expect("gate");
        while !state.resume_allowed {
            state = self.condvar.wait(state).expect("resume signal");
        }
        drop(state);
        let update = self
            .updates
            .get(update_index as usize)
            .expect("update exists")
            .clone();
        self.flow
            .lock()
            .expect("flow log")
            .push(ProviderCall::FetchUpdate(update_index));
        {
            let mut last = self.last_update_index.lock().expect("last update");
            *last = Some(update_index);
        }
        Ok(update)
    }

    fn resume_session(
        &self,
        session_id: SnapshotSessionId,
        _plan_id: &str,
        chunk_index: u64,
        update_index: u64,
    ) -> Result<SnapshotResumeState, Self::Error> {
        self.flow
            .lock()
            .expect("flow log")
            .push(ProviderCall::Resume(chunk_index, update_index));
        self.resumes
            .lock()
            .expect("resume log")
            .push((session_id, chunk_index, update_index));
        if chunk_index > self.total_chunks {
            return Err(PipelineError::SnapshotVerification(format!(
                "resume chunk index {chunk_index} exceeds total {}",
                self.total_chunks
            )));
        }
        if update_index > self.total_updates {
            return Err(PipelineError::SnapshotVerification(format!(
                "resume update index {update_index} exceeds total {}",
                self.total_updates
            )));
        }
        let expected_chunk_index = {
            let last = *self.last_chunk_index.lock().expect("last chunk");
            let confirmed = *self.confirmed_chunk_index.lock().expect("confirmed chunk");
            confirmed
                .or(last)
                .map(|index| index.saturating_add(1).min(self.total_chunks))
                .unwrap_or(0)
        };
        if chunk_index < expected_chunk_index {
            return Err(PipelineError::SnapshotVerification(format!(
                "resume chunk index {chunk_index} precedes next expected chunk {expected_chunk_index}"
            )));
        }
        if chunk_index > expected_chunk_index {
            return Err(PipelineError::SnapshotVerification(format!(
                "resume chunk index {chunk_index} skips ahead of next expected chunk {expected_chunk_index}"
            )));
        }
        let expected_update_index = {
            let last = *self.last_update_index.lock().expect("last update");
            let confirmed = *self
                .confirmed_update_index
                .lock()
                .expect("confirmed update");
            confirmed
                .or(last)
                .map(|index| index.saturating_add(1).min(self.total_updates))
                .unwrap_or(0)
        };
        if update_index < expected_update_index {
            return Err(PipelineError::SnapshotVerification(format!(
                "resume update index {update_index} precedes next expected update {expected_update_index}"
            )));
        }
        if update_index > expected_update_index {
            return Err(PipelineError::SnapshotVerification(format!(
                "resume update index {update_index} skips ahead of next expected update {expected_update_index}"
            )));
        }
        let mut state = self.gate.lock().expect("gate");
        state.resume_allowed = true;
        self.condvar.notify_all();
        Ok(SnapshotResumeState {
            next_chunk_index: chunk_index,
            next_update_index: update_index,
        })
    }

    fn acknowledge(
        &self,
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        index: u64,
    ) -> Result<(), Self::Error> {
        self.flow
            .lock()
            .expect("flow log")
            .push(ProviderCall::Ack(kind, index));
        self.acknowledgements
            .lock()
            .expect("acks")
            .push((session_id, kind, index));
        match kind {
            SnapshotItemKind::Chunk => {
                let mut confirmed = self.confirmed_chunk_index.lock().expect("confirmed chunk");
                *confirmed = Some(confirmed.map_or(index, |current| current.max(index)));
            }
            SnapshotItemKind::LightClientUpdate => {
                let mut confirmed = self
                    .confirmed_update_index
                    .lock()
                    .expect("confirmed update");
                *confirmed = Some(confirmed.map_or(index, |current| current.max(index)));
            }
            _ => {}
        }
        Ok(())
    }
}

fn sample_plan(root_hex: String) -> NetworkStateSyncPlan {
    let pruning = NetworkPruningEnvelope {
        schema_version: 1,
        parameter_version: 1,
        snapshot: NetworkPruningSnapshot {
            schema_version: 1,
            parameter_version: 1,
            block_height: 10,
            state_commitment: NetworkTaggedDigestHex::from("aa".repeat(32)),
        },
        segments: vec![NetworkPruningSegment {
            schema_version: 1,
            parameter_version: 1,
            segment_index: 0,
            start_height: 0,
            end_height: 10,
            segment_commitment: NetworkTaggedDigestHex::from("bb".repeat(32)),
        }],
        commitment: NetworkPruningCommitment {
            schema_version: 1,
            parameter_version: 1,
            aggregate_commitment: NetworkTaggedDigestHex::from("cc".repeat(32)),
        },
        binding_digest: NetworkTaggedDigestHex::from("dd".repeat(32)),
    };

    NetworkStateSyncPlan {
        snapshot: NetworkSnapshotSummary {
            height: 42,
            block_hash: "snapshot-block".into(),
            commitments: NetworkGlobalStateCommitments {
                global_state_root: root_hex.clone(),
                utxo_root: "11".repeat(32),
                reputation_root: "22".repeat(32),
                timetoke_root: "33".repeat(32),
                zsi_root: "44".repeat(32),
                proof_root: "55".repeat(32),
            },
            chain_commitment: "66".repeat(32),
        },
        tip: NetworkBlockMetadata {
            height: 50,
            hash: "tip-block".into(),
            timestamp: 99,
            previous_state_root: "77".repeat(32),
            new_state_root: "88".repeat(32),
            proof_hash: "99".repeat(32),
            pruning: Some(pruning.clone()),
            pruning_binding_digest: None,
            recursion_anchor: "anchor".into(),
        },
        chunks: vec![
            NetworkStateSyncChunk {
                start_height: 0,
                end_height: 24,
                requests: vec![NetworkReconstructionRequest {
                    height: 0,
                    block_hash: "block-0".into(),
                    tx_root: "tx-0".into(),
                    state_root: "state-0".into(),
                    utxo_root: "utxo-0".into(),
                    reputation_root: "rep-0".into(),
                    timetoke_root: "time-0".into(),
                    zsi_root: "zsi-0".into(),
                    proof_root: "proof-0".into(),
                    pruning: pruning.clone(),
                    previous_commitment: None,
                    payload_expectations: NetworkPayloadExpectations::default(),
                }],
                proofs: vec!["proof-chunk-0".into()],
            },
            NetworkStateSyncChunk {
                start_height: 25,
                end_height: 50,
                requests: vec![NetworkReconstructionRequest {
                    height: 25,
                    block_hash: "block-1".into(),
                    tx_root: "tx-1".into(),
                    state_root: "state-1".into(),
                    utxo_root: "utxo-1".into(),
                    reputation_root: "rep-1".into(),
                    timetoke_root: "time-1".into(),
                    zsi_root: "zsi-1".into(),
                    proof_root: "proof-1".into(),
                    pruning,
                    previous_commitment: None,
                    payload_expectations: NetworkPayloadExpectations::default(),
                }],
                proofs: vec!["proof-chunk-1".into()],
            },
        ],
        light_client_updates: vec![NetworkLightClientUpdate {
            height: 75,
            block_hash: "update-block".into(),
            state_root: "update-state".into(),
            proof_commitment: "aa".repeat(32),
            previous_commitment: Some("bb".repeat(32)),
            recursive_proof: "rec-proof".into(),
        }],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_stream_pause_and_resume() {
    let mut store = SnapshotStore::new(8);
    let payload = b"abcdefgh".to_vec();
    let root = store.insert(payload);
    let root_hex = hex::encode(root.as_bytes());
    let plan = sample_plan(root_hex.clone());
    let provider = MockSnapshotProvider::new(plan.clone(), store, root);

    let server_dir = tempdir().expect("server");
    let client_dir = tempdir().expect("client");

    let mut server = init_network(
        &server_dir,
        "server",
        TierLevel::Tl3,
        Some(provider.clone()),
    );
    let mut client = init_network(&client_dir, "client", TierLevel::Tl3, None);

    server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
        .expect("listen");

    let listen_addr = loop {
        match timeout(Duration::from_secs(5), server.next_event()).await {
            Ok(Ok(NetworkEvent::NewListenAddr(addr))) => break addr,
            Ok(_) => continue,
            Err(err) => panic!("listen timeout: {err:?}"),
        }
    };

    client.dial(listen_addr).expect("dial");

    let mut got_client_handshake = false;
    let mut got_server_handshake = false;

    timeout(Duration::from_secs(10), async {
        while !(got_client_handshake && got_server_handshake) {
            tokio::select! {
                event = client.next_event() => {
                    if let Ok(NetworkEvent::HandshakeCompleted { .. }) = event {
                        got_client_handshake = true;
                    }
                }
                event = server.next_event() => {
                    if let Ok(NetworkEvent::HandshakeCompleted { .. }) = event {
                        got_server_handshake = true;
                    }
                }
            }
        }
    })
    .await
    .expect("handshake");

    let session = SnapshotSessionId::new(7);
    client
        .start_snapshot_stream(session, server.local_peer_id(), root_hex)
        .expect("start stream");

    let mut plan_event: Option<NetworkStateSyncPlan> = None;
    let mut chunks = Vec::new();
    let mut updates = Vec::new();
    let mut stream_completed = false;
    let mut resumed = false;

    timeout(Duration::from_secs(20), async {
        while !stream_completed {
            tokio::select! {
                event = client.next_event() => {
                    match event.expect("client event") {
                        NetworkEvent::SnapshotPlan { plan, .. } => {
                            plan_event = Some(plan);
                        }
                        NetworkEvent::SnapshotChunk { index, chunk, .. } => {
                            chunks.push((index, chunk.clone()));
                            if index == 0 && !resumed {
                                let next_chunk = index + 1;
                                let next_update = 0;
                                client.force_clear_snapshot_pending(session);
                                client
                                    .resume_snapshot_stream(
                                        session,
                                        root_hex.clone(),
                                        next_chunk,
                                        next_update,
                                    )
                                    .expect("resume request");
                                resumed = true;
                            }
                        }
                        NetworkEvent::SnapshotUpdate { index, update, .. } => {
                            updates.push((index, update));
                        }
                        NetworkEvent::SnapshotStreamCompleted { .. } => {
                            stream_completed = true;
                        }
                        _ => {}
                    }
                }
                event = server.next_event() => {
                    if let Ok(NetworkEvent::SnapshotStreamError { reason, .. }) = event {
                        panic!("server stream error: {reason}");
                    }
                }
            }
        }
    })
    .await
    .expect("stream complete");

    let plan_event = plan_event.expect("plan");
    assert_eq!(
        plan_event.snapshot.commitments.global_state_root,
        plan.snapshot.commitments.global_state_root,
    );

    assert_eq!(chunks.len(), 2, "expected two snapshot chunks");
    assert_eq!(chunks[0].0, 0);
    assert_eq!(chunks[1].0, 1);
    assert_eq!(chunks[0].1.data, b"abcdefgh"[..4]);
    assert_eq!(chunks[1].1.data, b"abcdefgh"[4..]);

    assert_eq!(updates.len(), 1, "expected single update");
    assert_eq!(updates[0].0, 0);
    assert_eq!(
        updates[0].1.block_hash,
        plan.light_client_updates[0].block_hash
    );

    let flow_log = provider.flow_log();
    assert!(flow_log.contains(&ProviderCall::FetchPlan));
    assert!(flow_log.contains(&ProviderCall::FetchChunk(0)));
    assert!(flow_log.contains(&ProviderCall::FetchChunk(1)));
    assert!(flow_log.contains(&ProviderCall::FetchUpdate(0)));
    assert!(flow_log.contains(&ProviderCall::Resume(1, 0)));
    assert!(flow_log.contains(&ProviderCall::Ack(SnapshotItemKind::Chunk, 0)));
    assert!(flow_log.contains(&ProviderCall::Ack(SnapshotItemKind::Chunk, 1)));
    assert!(flow_log.contains(&ProviderCall::Ack(SnapshotItemKind::LightClientUpdate, 0)));

    let resume_calls = provider.resume_calls();
    assert_eq!(resume_calls, vec![(session, 1, 0)]);

    let acknowledgements = provider.acknowledgements();
    assert!(acknowledgements.contains(&(session, SnapshotItemKind::Chunk, 0)));
    assert!(acknowledgements.contains(&(session, SnapshotItemKind::Chunk, 1)));
    assert!(acknowledgements.contains(&(session, SnapshotItemKind::LightClientUpdate, 0)));

    drop(client);
    drop(server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_resume_rejects_invalid_offsets() {
    let mut store = SnapshotStore::new(8);
    let payload = b"abcdefgh".to_vec();
    let root = store.insert(payload);
    let root_hex = hex::encode(root.as_bytes());
    let plan = sample_plan(root_hex.clone());
    let provider = MockSnapshotProvider::new(plan.clone(), store, root);

    let server_dir = tempdir().expect("server");
    let client_dir = tempdir().expect("client");

    let mut server = init_network(
        &server_dir,
        "server",
        TierLevel::Tl3,
        Some(provider.clone()),
    );
    let mut client = init_network(&client_dir, "client", TierLevel::Tl3, None);

    server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
        .expect("listen");

    let listen_addr = loop {
        match timeout(Duration::from_secs(5), server.next_event()).await {
            Ok(Ok(NetworkEvent::NewListenAddr(addr))) => break addr,
            Ok(_) => continue,
            Err(err) => panic!("listen timeout: {err:?}"),
        }
    };

    client.dial(listen_addr).expect("dial");

    let mut got_client_handshake = false;
    let mut got_server_handshake = false;

    timeout(Duration::from_secs(10), async {
        while !(got_client_handshake && got_server_handshake) {
            tokio::select! {
                event = client.next_event() => {
                    if let Ok(NetworkEvent::HandshakeCompleted { .. }) = event {
                        got_client_handshake = true;
                    }
                }
                event = server.next_event() => {
                    if let Ok(NetworkEvent::HandshakeCompleted { .. }) = event {
                        got_server_handshake = true;
                    }
                }
            }
        }
    })
    .await
    .expect("handshake");

    let session = SnapshotSessionId::new(11);
    client
        .start_snapshot_stream(session, server.local_peer_id(), root_hex)
        .expect("start stream");

    let mut resume_attempted = false;
    let mut error_reason: Option<String> = None;

    timeout(Duration::from_secs(20), async {
        while error_reason.is_none() {
            tokio::select! {
                event = client.next_event() => {
                    match event.expect("client event") {
                        NetworkEvent::SnapshotPlan { .. } => {}
                        NetworkEvent::SnapshotChunk { session: event_session, index, .. } => {
                            if index == 0 && !resume_attempted {
                                resume_attempted = true;
                                client.force_clear_snapshot_pending(event_session);
                                client
                                    .resume_snapshot_stream(
                                        event_session,
                                        root_hex.clone(),
                                        0,
                                        0,
                                    )
                                    .expect("resume request");
                            }
                        }
                        NetworkEvent::SnapshotStreamError { reason, .. } => {
                            error_reason = Some(reason);
                        }
                        _ => {}
                    }
                }
                event = server.next_event() => {
                    if let Ok(NetworkEvent::SnapshotStreamError { reason, .. }) = event {
                        panic!("server stream error: {reason}");
                    }
                }
            }
        }
    })
    .await
    .expect("resume error observed");

    let reason = error_reason.expect("resume error");
    assert!(
        reason.contains("resume chunk index 0 precedes next expected chunk 1"),
        "unexpected error message: {reason}"
    );

    let flow_log = provider.flow_log();
    assert!(flow_log.contains(&ProviderCall::Resume(0, 0)));

    drop(client);
    drop(server);
}
