use std::collections::{HashMap, HashSet};
use std::env;
use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use libp2p::PeerId;
use reqwest::Client;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;
use tokio::runtime::Builder;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Instant};

use rpp_chain::config::{GenesisAccount, NodeConfig, WalletConfig};
use rpp_chain::crypto::{
    address_from_public_key, load_or_generate_keypair, load_or_generate_vrf_keypair,
};
use rpp_chain::gossip::{spawn_node_event_worker, NodeGossipProcessor};
use rpp_chain::node::{
    ConsensusStatus as RuntimeConsensusStatus, Node, NodeHandle, NodeStatus as RuntimeNodeStatus,
};
use rpp_chain::orchestration::{PipelineOrchestrator, PipelineStage};
use rpp_chain::runtime::node_runtime::node::{NodeEvent, NodeRuntimeConfig};
use rpp_chain::runtime::node_runtime::{
    IdentityProfile as RuntimeIdentityProfile, NodeHandle as P2pHandle, NodeInner as P2pNode,
};
#[cfg(feature = "vendor_electrs")]
use rpp_chain::runtime::sync::{
    PayloadProvider, ReconstructionRequest, RuntimeRecursiveProofVerifier,
};
use rpp_chain::runtime::types::proofs::TransactionProofBundle;
use rpp_chain::runtime::types::transaction::{SignedTransaction, Transaction};
use rpp_chain::runtime::RuntimeMetrics;
use rpp_chain::types::Address;
use rpp_chain::wallet::Wallet;
#[cfg(feature = "vendor_electrs")]
use rpp_chain::{
    errors::{ChainError, ChainResult},
    storage::Storage,
    types::BlockPayload,
};
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::config::ElectrsConfig;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::firewood_adapter::RuntimeAdapters;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::init::{initialize, ElectrsHandles};

const PROCESS_INIT_TIMEOUT: Duration = Duration::from_secs(90);
const PROCESS_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);

struct PreparedClusterNode {
    index: usize,
    temp_dir: TempDir,
    config: NodeConfig,
    address: String,
    listen_addr: String,
}

struct PreparedCluster {
    nodes: Vec<PreparedClusterNode>,
    genesis_accounts: Vec<GenesisAccount>,
}

impl PreparedCluster {
    fn prepare_with<F>(count: usize, mut configure: F) -> Result<Self>
    where
        F: FnMut(&mut NodeConfig, usize) -> Result<()>,
    {
        if count < 2 {
            return Err(anyhow!(
                "test cluster requires at least two nodes to initialise"
            ));
        }

        let mut prepared = Vec::with_capacity(count);
        for index in 0..count {
            let temp_dir = TempDir::new().context("failed to create node temp dir")?;
            let node_root = temp_dir.path().to_path_buf();
            let data_dir = node_root.join("data");
            let keys_dir = node_root.join("keys");
            std::fs::create_dir_all(&data_dir)
                .with_context(|| format!("failed to create data dir for node {index}"))?;
            std::fs::create_dir_all(&keys_dir)
                .with_context(|| format!("failed to create keys dir for node {index}"))?;

            let mut config = NodeConfig::default();
            config.data_dir = data_dir.clone();
            config.snapshot_dir = data_dir.join("snapshots");
            config.proof_cache_dir = data_dir.join("proofs");
            config.consensus_pipeline_path = data_dir.join("p2p/consensus_pipeline.json");
            config.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
            config.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
            config.key_path = keys_dir.join("node.toml");
            config.p2p_key_path = keys_dir.join("p2p.toml");
            config.vrf_key_path = keys_dir.join("vrf.toml");
            config.block_time_ms = 200;
            config.mempool_limit = 256;
            config.target_validator_count = count;
            config.malachite.validator.validator_set_size = count;
            config.rpc_listen = rpc_socket(index)?;
            let (listen_addr, _) = random_listen_addr()?;
            config.p2p.listen_addr = listen_addr.clone();
            config.rollout.feature_gates.pruning = false;
            config.rollout.feature_gates.recursive_proofs = false;
            config.rollout.feature_gates.reconstruction = false;
            config.rollout.feature_gates.consensus_enforcement = false;

            let keypair = load_or_generate_keypair(&config.key_path)
                .with_context(|| format!("failed to initialise node key for node {index}"))?;
            load_or_generate_vrf_keypair(&config.vrf_key_path)
                .with_context(|| format!("failed to initialise VRF key for node {index}"))?;
            let address = address_from_public_key(&keypair.public);

            configure(&mut config, index)?;

            prepared.push(PreparedClusterNode {
                index,
                temp_dir,
                config,
                address,
                listen_addr,
            });
        }

        let genesis_accounts = prepared
            .iter()
            .map(|node| GenesisAccount {
                address: node.address.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            })
            .collect::<Vec<_>>();

        let listen_addrs = prepared
            .iter()
            .map(|node| node.listen_addr.clone())
            .collect::<Vec<_>>();

        for node in prepared.iter_mut() {
            node.config.genesis.accounts = genesis_accounts.clone();
            node.config.genesis.chain_id = "test-cluster".to_string();
            node.config.p2p.bootstrap_peers = listen_addrs
                .iter()
                .enumerate()
                .filter_map(|(peer_index, addr)| {
                    if peer_index == node.index {
                        None
                    } else {
                        Some(addr.clone())
                    }
                })
                .collect();
        }

        Ok(Self {
            nodes: prepared,
            genesis_accounts,
        })
    }
}

#[cfg(feature = "vendor_electrs")]
#[derive(Clone)]
struct ClusterPayloadProvider {
    storage: Storage,
}

#[cfg(feature = "vendor_electrs")]
impl ClusterPayloadProvider {
    fn new(storage: &Storage) -> Self {
        Self {
            storage: storage.clone(),
        }
    }
}

#[cfg(feature = "vendor_electrs")]
impl PayloadProvider for ClusterPayloadProvider {
    fn fetch_payload(&self, request: &ReconstructionRequest) -> ChainResult<BlockPayload> {
        let record = self
            .storage
            .read_block_record(request.height)?
            .ok_or_else(|| {
                ChainError::Config(format!(
                    "cluster block payload for height {} not found",
                    request.height
                ))
            })?;
        let payload = record.payload.ok_or_else(|| {
            ChainError::Config(format!(
                "cluster block payload for height {} is not available",
                request.height
            ))
        })?;
        Ok(payload)
    }
}

/// Represents a running validator node inside the [`TestCluster`].
pub struct TestClusterNode {
    pub index: usize,
    pub config: NodeConfig,
    pub node_handle: NodeHandle,
    pub p2p_handle: P2pHandle,
    pub orchestrator: Arc<PipelineOrchestrator>,
    pub wallet: Arc<Wallet>,
    pub node_task: JoinHandle<Result<()>>,
    pub p2p_task: JoinHandle<Result<()>>,
    pub gossip_task: JoinHandle<Result<()>>,
    temp_dir: TempDir,
    connection_task: JoinHandle<()>,
    connected_peers: Arc<RwLock<HashSet<PeerId>>>,
}

impl TestClusterNode {
    /// Wait until the node observes the expected number of connected peers.
    pub async fn wait_for_peer_count(&self, expected: usize, timeout: Duration) -> Result<()> {
        if expected == 0 {
            return Ok(());
        }
        let deadline = Instant::now() + timeout;
        loop {
            let current = self.connected_peers.read().await.len();
            if current >= expected {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(anyhow!(
                    "node {0} saw {1} peers after waiting {2:?} (expected {3})",
                    self.index,
                    current,
                    timeout,
                    expected,
                ));
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    fn spawn_connection_tracker(
        handle: &P2pHandle,
    ) -> (Arc<RwLock<HashSet<PeerId>>>, JoinHandle<()>) {
        let peers = Arc::new(RwLock::new(HashSet::new()));
        let mut events = handle.subscribe();
        let tracker_peers = peers.clone();
        let task = tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(NodeEvent::PeerConnected { peer, .. }) => {
                        tracker_peers.write().await.insert(peer);
                    }
                    Ok(NodeEvent::PeerDisconnected { peer }) => {
                        tracker_peers.write().await.remove(&peer);
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        });
        (peers, task)
    }

    pub async fn restart(&mut self) -> Result<()> {
        let identity = self
            .node_handle
            .network_identity_profile()
            .with_context(|| format!("failed to fetch identity for node {}", self.index))?;

        self.orchestrator.shutdown();

        self.p2p_handle
            .shutdown()
            .await
            .map_err(|err| anyhow!("failed to stop libp2p node {0}: {1}", self.index, err))?;

        self.node_handle
            .stop()
            .await
            .with_context(|| format!("failed to stop node runtime for node {}", self.index))?;

        let old_node_task = std::mem::replace(
            &mut self.node_task,
            tokio::spawn(async { Result::<(), anyhow::Error>::Ok(()) }),
        );
        let old_p2p_task = std::mem::replace(
            &mut self.p2p_task,
            tokio::task::spawn_blocking(|| -> Result<()> { Ok(()) }),
        );
        let old_gossip_task = std::mem::replace(&mut self.gossip_task, tokio::spawn(async { () }));
        let old_connection_task =
            std::mem::replace(&mut self.connection_task, tokio::spawn(async { () }));
        let _ = old_node_task.await;
        let _ = old_p2p_task.await;
        let _ = old_gossip_task.await;
        let _ = old_connection_task.await;

        let config = self.config.clone();
        let node = tokio::task::spawn_blocking({
            let config = config.clone();
            move || Node::new(config)
        })
        .await
        .context("node runtime restart task panicked")?
        .with_context(|| format!("failed to construct node runtime for node {}", self.index))?;
        let node_handle = node.handle();

        let mut runtime_config = NodeRuntimeConfig::from(&config);
        runtime_config.metrics = RuntimeMetrics::noop();
        runtime_config.identity = Some(RuntimeIdentityProfile::from(identity));
        let (p2p_runtime, p2p_handle) = P2pNode::new(runtime_config).with_context(|| {
            format!(
                "failed to initialise libp2p runtime for node {}",
                self.index
            )
        })?;

        node_handle.attach_p2p(p2p_handle.clone()).await;

        let (connected_peers, connection_task) =
            TestClusterNode::spawn_connection_tracker(&p2p_handle);

        let (orchestrator, shutdown_rx) =
            PipelineOrchestrator::new(node_handle.clone(), Some(p2p_handle.clone()));
        let orchestrator = Arc::new(orchestrator);
        orchestrator.spawn(shutdown_rx.clone());

        let events = p2p_handle.subscribe();
        let proof_storage_path = config.proof_cache_dir.join("gossip_proofs.json");
        let processor = Arc::new(NodeGossipProcessor::new(
            node_handle.clone(),
            proof_storage_path,
        ));
        let gossip_task = spawn_node_event_worker(events, processor, Some(shutdown_rx.clone()));

        let storage = node_handle.storage();
        #[cfg(feature = "vendor_electrs")]
        let mut electrs_context: Option<(ElectrsConfig, ElectrsHandles)> = None;
        #[cfg(feature = "vendor_electrs")]
        {
            let mut wallet_config = WalletConfig::default();
            wallet_config.data_dir = self.temp_dir.path().join("wallet");
            wallet_config.key_path = config.key_path.clone();
            wallet_config
                .ensure_directories()
                .map_err(|err| anyhow!(err))?;
            if let Some(cfg) = wallet_config.electrs.clone() {
                let firewood_dir = wallet_config.electrs_firewood_dir();
                let index_dir = wallet_config.electrs_index_dir();
                let provider = Arc::new(ClusterPayloadProvider::new(&storage));
                let verifier = Arc::new(RuntimeRecursiveProofVerifier::default());
                let runtime_adapters = RuntimeAdapters::new(
                    Arc::new(storage.clone()),
                    node_handle.clone(),
                    orchestrator.as_ref().clone(),
                    provider,
                    verifier,
                );
                let handles = initialize(&cfg, firewood_dir, index_dir, Some(runtime_adapters))
                    .with_context(|| {
                        format!(
                            "failed to initialise electrs for cluster node {}",
                            self.index
                        )
                    })?;
                electrs_context = Some((cfg, handles));
            }
        }

        let wallet_key = load_or_generate_keypair(&config.key_path).with_context(|| {
            format!("failed to load node key for wallet on node {}", self.index)
        })?;
        let wallet = {
            #[cfg(feature = "vendor_electrs")]
            {
                if let Some((cfg, handles)) = electrs_context {
                    Arc::new(
                        Wallet::with_electrs(storage.clone(), wallet_key, cfg, handles)
                            .map_err(|err| anyhow!(err))?,
                    )
                } else {
                    Arc::new(Wallet::new(storage.clone(), wallet_key))
                }
            }
            #[cfg(not(feature = "vendor_electrs"))]
            {
                Arc::new(Wallet::new(storage.clone(), wallet_key))
            }
        };

        let index = self.index;
        let node_task = tokio::spawn(async move {
            node.start()
                .await
                .with_context(|| format!("node {index} runtime terminated"))
        });

        let p2p_task = tokio::task::spawn_blocking(move || -> Result<()> {
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .context("failed to build libp2p executor")?;
            runtime
                .block_on(async move {
                    p2p_runtime
                        .run()
                        .await
                        .with_context(|| "libp2p runtime exited unexpectedly")
                })
                .with_context(|| "libp2p runtime stopped")?;
            Ok(())
        });

        self.node_handle = node_handle;
        self.p2p_handle = p2p_handle;
        self.orchestrator = orchestrator;
        self.wallet = wallet;
        self.node_task = node_task;
        self.p2p_task = p2p_task;
        self.gossip_task = gossip_task;
        self.connection_task = connection_task;
        self.connected_peers = connected_peers;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ConsensusSnapshot {
    pub height: u64,
    pub block_hash: Option<String>,
    pub pending_votes: usize,
    pub node_pending_votes: usize,
}

impl ConsensusSnapshot {
    fn new(
        height: u64,
        block_hash: Option<String>,
        pending_votes: usize,
        node_pending_votes: usize,
    ) -> Self {
        Self {
            height,
            block_hash,
            pending_votes,
            node_pending_votes,
        }
    }
}

/// Helper structure that provides access to a fully wired local network of validators.
pub struct TestCluster {
    nodes: Vec<TestClusterNode>,
    genesis_accounts: Vec<GenesisAccount>,
}

impl TestCluster {
    /// Boot a new cluster containing `count` validators.
    pub async fn start(count: usize) -> Result<Self> {
        Self::start_with(count, |_, _| Ok(())).await
    }

    pub async fn start_with<F>(count: usize, mut configure: F) -> Result<Self>
    where
        F: FnMut(&mut NodeConfig, usize) -> Result<()>,
    {
        let prepared =
            PreparedCluster::prepare_with(count, |config, index| configure(config, index))?;

        let PreparedCluster {
            nodes: prepared_nodes,
            genesis_accounts,
        } = prepared;

        let mut nodes = Vec::with_capacity(prepared_nodes.len());
        for PreparedClusterNode {
            index,
            temp_dir,
            config,
            ..
        } in prepared_nodes
        {
            let mut config = config;
            let node = tokio::task::spawn_blocking({
                let config = config.clone();
                move || Node::new(config)
            })
            .await
            .context("node runtime initialisation task panicked")?
            .with_context(|| format!("failed to construct node runtime for node {index}"))?;
            let node_handle = node.handle();
            let network_identity = node
                .network_identity_profile()
                .with_context(|| format!("failed to derive network identity for node {index}"))?;
            let mut runtime_config = NodeRuntimeConfig::from(&config);
            runtime_config.metrics = RuntimeMetrics::noop();
            runtime_config.identity = Some(network_identity.into());
            let (p2p_runtime, p2p_handle) = P2pNode::new(runtime_config)
                .with_context(|| format!("failed to initialise libp2p runtime for node {index}"))?;

            node_handle.attach_p2p(p2p_handle.clone()).await;

            let (connected_peers, connection_task) =
                TestClusterNode::spawn_connection_tracker(&p2p_handle);

            let (orchestrator, shutdown_rx) =
                PipelineOrchestrator::new(node_handle.clone(), Some(p2p_handle.clone()));
            let orchestrator = Arc::new(orchestrator);
            orchestrator.spawn(shutdown_rx.clone());

            let events = p2p_handle.subscribe();
            let proof_storage_path = config.proof_cache_dir.join("gossip_proofs.json");
            let processor = Arc::new(NodeGossipProcessor::new(
                node_handle.clone(),
                proof_storage_path,
            ));
            let gossip_task = spawn_node_event_worker(events, processor, Some(shutdown_rx.clone()));

            let storage = node_handle.storage();
            #[cfg(feature = "vendor_electrs")]
            let mut electrs_context: Option<(ElectrsConfig, ElectrsHandles)> = None;
            #[cfg(feature = "vendor_electrs")]
            {
                let mut wallet_config = WalletConfig::default();
                wallet_config.data_dir = node_root.join("wallet");
                wallet_config.key_path = config.key_path.clone();
                wallet_config
                    .ensure_directories()
                    .map_err(|err| anyhow!(err))?;
                if let Some(cfg) = wallet_config.electrs.clone() {
                    let firewood_dir = wallet_config.electrs_firewood_dir();
                    let index_dir = wallet_config.electrs_index_dir();
                    let provider = Arc::new(ClusterPayloadProvider::new(&storage));
                    let verifier = Arc::new(RuntimeRecursiveProofVerifier::default());
                    let runtime_adapters = RuntimeAdapters::new(
                        Arc::new(storage.clone()),
                        node_handle.clone(),
                        orchestrator.as_ref().clone(),
                        provider,
                        verifier,
                    );
                    let handles = initialize(&cfg, firewood_dir, index_dir, Some(runtime_adapters))
                        .with_context(|| {
                            format!("failed to initialise electrs for cluster node {index}")
                        })?;
                    electrs_context = Some((cfg, handles));
                }
            }

            let wallet_key = load_or_generate_keypair(&config.key_path)
                .with_context(|| format!("failed to load node key for wallet on node {index}"))?;
            let wallet = {
                #[cfg(feature = "vendor_electrs")]
                {
                    if let Some((cfg, handles)) = electrs_context {
                        Arc::new(
                            Wallet::with_electrs(storage.clone(), wallet_key, cfg, handles)
                                .map_err(|err| anyhow!(err))?,
                        )
                    } else {
                        Arc::new(Wallet::new(storage.clone(), wallet_key))
                    }
                }
                #[cfg(not(feature = "vendor_electrs"))]
                {
                    Arc::new(Wallet::new(storage.clone(), wallet_key))
                }
            };

            let node_task = tokio::spawn(async move {
                node.start()
                    .await
                    .with_context(|| format!("node {index} runtime terminated"))
            });

            let p2p_task = tokio::task::spawn_blocking(move || -> Result<()> {
                let runtime = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("failed to build libp2p executor")?;
                runtime
                    .block_on(async move {
                        p2p_runtime
                            .run()
                            .await
                            .with_context(|| "libp2p runtime exited unexpectedly")
                    })
                    .with_context(|| "libp2p runtime stopped")?;
                Ok(())
            });

            nodes.push(TestClusterNode {
                index,
                config,
                node_handle,
                p2p_handle,
                orchestrator,
                wallet,
                node_task,
                p2p_task,
                gossip_task,
                temp_dir,
                connection_task,
                connected_peers,
            });
        }

        Ok(Self {
            nodes,
            genesis_accounts,
        })
    }

    /// Returns references to the running cluster nodes.
    pub fn nodes(&self) -> &[TestClusterNode] {
        &self.nodes
    }

    pub fn nodes_mut(&mut self) -> &mut [TestClusterNode] {
        &mut self.nodes
    }

    /// Returns the genesis validator set shared by all nodes.
    pub fn genesis_accounts(&self) -> &[GenesisAccount] {
        &self.genesis_accounts
    }

    pub fn consensus_snapshots(&self) -> Result<Vec<ConsensusSnapshot>> {
        self.nodes
            .iter()
            .map(|node| {
                let consensus = node
                    .node_handle
                    .consensus_status()
                    .with_context(|| format!("fetch consensus status for node {}", node.index))?;
                let status = node
                    .node_handle
                    .node_status()
                    .with_context(|| format!("fetch node status for node {}", node.index))?;
                Ok(ConsensusSnapshot::new(
                    consensus.height,
                    consensus.block_hash.clone(),
                    consensus.pending_votes,
                    status.pending_votes,
                ))
            })
            .collect()
    }

    pub async fn wait_for_quorum_progress(
        &self,
        baseline: &[ConsensusSnapshot],
        timeout: Duration,
    ) -> Result<()> {
        if baseline.len() != self.nodes.len() {
            return Err(anyhow!(
                "baseline snapshot count {} does not match cluster size {}",
                baseline.len(),
                self.nodes.len()
            ));
        }

        let deadline = Instant::now() + timeout;
        let mut pending: Vec<(
            usize,
            ConsensusSnapshot,
            RuntimeConsensusStatus,
            RuntimeNodeStatus,
        )> = Vec::with_capacity(self.nodes.len());

        loop {
            pending.clear();

            for (node, snapshot) in self.nodes.iter().zip(baseline.iter()) {
                let consensus = node
                    .node_handle
                    .consensus_status()
                    .with_context(|| format!("poll consensus status for node {}", node.index))?;
                let status = node
                    .node_handle
                    .node_status()
                    .with_context(|| format!("poll node status for node {}", node.index))?;

                let progressed = consensus.quorum_reached
                    && (consensus.height > snapshot.height
                        || consensus.block_hash != snapshot.block_hash);

                if progressed {
                    continue;
                }

                pending.push((node.index, snapshot.clone(), consensus, status));
            }

            if pending.is_empty() {
                return Ok(());
            }

            if Instant::now() >= deadline {
                let mut message = String::from("quorum condition not satisfied for nodes: ");
                for (index, snapshot, consensus, status) in pending.iter() {
                    use std::fmt::Write;
                    let _ = write!(
                        &mut message,
                        "[node {} baseline height={} hash={:?} pending_votes={} node_pending={} -> height={} hash={:?} quorum={} pending_votes={} node_pending={}] ",
                        index,
                        snapshot.height,
                        snapshot.block_hash,
                        snapshot.pending_votes,
                        snapshot.node_pending_votes,
                        consensus.height,
                        consensus.block_hash,
                        consensus.quorum_reached,
                        consensus.pending_votes,
                        status.pending_votes
                    );
                }
                return Err(anyhow!(message));
            }

            sleep(Duration::from_millis(200)).await;
        }
    }

    /// Wait until every node has connected to all other peers.
    pub async fn wait_for_full_mesh(&self, timeout: Duration) -> Result<()> {
        let expected = self.nodes.len().saturating_sub(1);
        for node in &self.nodes {
            node.wait_for_peer_count(expected, timeout).await?;
        }
        Ok(())
    }

    /// Gracefully stop the cluster and clean up resources.
    pub async fn shutdown(mut self) -> Result<()> {
        for node in &self.nodes {
            node.orchestrator.shutdown();
        }
        for node in &self.nodes {
            node.p2p_handle
                .shutdown()
                .await
                .map_err(|err| anyhow!("failed to stop libp2p node {0}: {1}", node.index, err))?;
        }
        for node in &mut self.nodes {
            node.node_task.abort();
        }
        for node in self.nodes {
            let _ = node.node_task.await;
            let _ = node.gossip_task.await;
            let _ = node.connection_task.await;
            let _ = node.p2p_task.await;
        }
        Ok(())
    }
}

pub struct ProcessClusterNode {
    pub index: usize,
    pub config_path: PathBuf,
    pub rpc_addr: SocketAddr,
    pub p2p_listen_addr: String,
    pub child: Child,
    temp_dir: TempDir,
    stdout_task: Option<JoinHandle<()>>,
    stderr_task: Option<JoinHandle<()>>,
}

pub struct ProcessTestCluster {
    nodes: Vec<ProcessClusterNode>,
    genesis_accounts: Vec<GenesisAccount>,
    binary: String,
    client: Client,
}

impl ProcessTestCluster {
    pub async fn start(count: usize) -> Result<Self> {
        Self::start_with(count, |_, _| Ok(())).await
    }

    pub async fn start_with<F>(count: usize, mut configure: F) -> Result<Self>
    where
        F: FnMut(&mut NodeConfig, usize) -> Result<()>,
    {
        let prepared =
            PreparedCluster::prepare_with(count, |config, index| configure(config, index))?;

        let PreparedCluster {
            nodes: prepared_nodes,
            genesis_accounts,
        } = prepared;

        let binary = env::var("CARGO_BIN_EXE_rpp-node")
            .context("environment variable CARGO_BIN_EXE_rpp-node is not set")?;

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .context("failed to build HTTP client for process cluster")?;

        let mut nodes = Vec::with_capacity(prepared_nodes.len());
        for PreparedClusterNode {
            index,
            temp_dir,
            mut config,
            ..
        } in prepared_nodes
        {
            let config_path = temp_dir.path().join("node.toml");
            config
                .ensure_directories()
                .with_context(|| format!("failed to prepare directories for node {index}"))?;
            config
                .save(&config_path)
                .with_context(|| format!("failed to persist config for node {index}"))?;

            let mut command = Command::new(&binary);
            command
                .arg("node")
                .arg("--config")
                .arg(&config_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let mut child = command
                .spawn()
                .with_context(|| format!("failed to spawn rpp-node process for node {index}"))?;

            let stdout_task = spawn_output_task(index, "stdout", child.stdout.take());
            let stderr_task = spawn_output_task(index, "stderr", child.stderr.take());

            wait_for_process_ready(&client, &mut child, config.rpc_listen, index).await?;

            nodes.push(ProcessClusterNode {
                index,
                config_path,
                rpc_addr: config.rpc_listen,
                p2p_listen_addr: config.p2p.listen_addr.clone(),
                child,
                temp_dir,
                stdout_task,
                stderr_task,
            });
        }

        Ok(Self {
            nodes,
            genesis_accounts,
            binary,
            client,
        })
    }

    pub fn nodes(&self) -> &[ProcessClusterNode] {
        &self.nodes
    }

    pub fn nodes_mut(&mut self) -> &mut [ProcessClusterNode] {
        &mut self.nodes
    }

    pub fn genesis_accounts(&self) -> &[GenesisAccount] {
        &self.genesis_accounts
    }

    pub fn binary(&self) -> &str {
        &self.binary
    }

    pub fn client(&self) -> Client {
        self.client.clone()
    }

    pub async fn shutdown(mut self) -> Result<()> {
        for node in &mut self.nodes {
            if node.child.id().is_some() {
                if let Err(err) = send_ctrl_c(&node.child) {
                    tracing::warn!(
                        target = "tests::cluster::process",
                        node = node.index,
                        error = %err,
                        "failed to send CTRL+C to process cluster node"
                    );
                }
            }
        }

        for node in &mut self.nodes {
            let started = Instant::now();
            loop {
                match node.child.try_wait() {
                    Ok(Some(status)) => {
                        if !status.success() {
                            return Err(anyhow!(
                                "process cluster node {} exited with status {}",
                                node.index,
                                status
                            ));
                        }
                        break;
                    }
                    Ok(None) => {
                        if started.elapsed() > PROCESS_SHUTDOWN_TIMEOUT {
                            node.child.kill().with_context(|| {
                                format!(
                                    "failed to terminate process cluster node {} after timeout",
                                    node.index
                                )
                            })?;
                            let status = node.child.wait().with_context(|| {
                                format!("failed to reap process cluster node {}", node.index)
                            })?;
                            if !status.success() {
                                return Err(anyhow!(
                                    "process cluster node {} exited with status {}",
                                    node.index,
                                    status
                                ));
                            }
                            break;
                        }
                    }
                    Err(err) => {
                        return Err(err).with_context(|| {
                            format!("failed to query process status for node {}", node.index)
                        });
                    }
                }
                sleep(Duration::from_millis(200)).await;
            }
        }

        for mut node in self.nodes {
            if let Some(task) = node.stdout_task.take() {
                let _ = task.await;
            }
            if let Some(task) = node.stderr_task.take() {
                let _ = task.await;
            }
        }

        Ok(())
    }
}

impl ProcessClusterNode {
    pub async fn respawn(&mut self, binary: &str, client: &Client) -> Result<()> {
        if self.child.id().is_some() {
            if let Err(err) = send_ctrl_c(&self.child) {
                tracing::warn!(
                    target = "tests::cluster::process",
                    node = self.index,
                    error = %err,
                    "failed to send CTRL+C to process cluster node during respawn"
                );
            }
        }

        let started = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return Err(anyhow!(
                            "process cluster node {} exited with status {} during respawn",
                            self.index,
                            status
                        ));
                    }
                    break;
                }
                Ok(None) => {
                    if started.elapsed() > PROCESS_SHUTDOWN_TIMEOUT {
                        self.child.kill().with_context(|| {
                            format!(
                                "failed to terminate process cluster node {} during respawn",
                                self.index
                            )
                        })?;
                        let status = self.child.wait().with_context(|| {
                            format!("failed to reap process cluster node {}", self.index)
                        })?;
                        if !status.success() {
                            return Err(anyhow!(
                                "process cluster node {} exited with status {} during respawn",
                                self.index,
                                status
                            ));
                        }
                        break;
                    }
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!(
                            "failed to query process status for node {} during respawn",
                            self.index
                        )
                    });
                }
            }
            sleep(Duration::from_millis(200)).await;
        }

        if let Some(task) = self.stdout_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.stderr_task.take() {
            let _ = task.await;
        }

        let mut command = Command::new(binary);
        command
            .arg("node")
            .arg("--config")
            .arg(&self.config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().with_context(|| {
            format!(
                "failed to spawn rpp-node process for node {} during respawn",
                self.index
            )
        })?;

        let stdout_task = spawn_output_task(self.index, "stdout", child.stdout.take());
        let stderr_task = spawn_output_task(self.index, "stderr", child.stderr.take());

        wait_for_process_ready(client, &mut child, self.rpc_addr, self.index).await?;

        self.child = child;
        self.stdout_task = stdout_task;
        self.stderr_task = stderr_task;

        Ok(())
    }

    pub fn harness(&self) -> Result<ProcessNodeHarness> {
        ProcessNodeHarness::connect(self)
    }
}

#[derive(Clone)]
pub struct ProcessNodeHarness {
    client: Client,
    base_url: Url,
}

impl ProcessNodeHarness {
    pub fn connect(node: &ProcessClusterNode) -> Result<Self> {
        let client = Client::builder()
            .build()
            .context("build process node harness client")?;
        let mut base_url = Url::parse(&format!("http://{}", node.rpc_addr))
            .context("parse process node RPC URL")?;
        if base_url.path() != "/" {
            base_url.set_path("/");
        }
        Ok(Self { client, base_url })
    }

    pub fn rpc(&self) -> ProcessNodeRpcClient {
        ProcessNodeRpcClient::new(self.client.clone(), self.base_url.clone())
    }

    pub fn orchestrator(&self) -> ProcessNodeOrchestratorClient {
        ProcessNodeOrchestratorClient::new(self.client.clone(), self.base_url.clone())
    }

    pub async fn wait_for_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let url = self
            .base_url
            .join("health/ready")
            .context("construct ready probe URL")?;
        loop {
            if Instant::now() >= deadline {
                return Err(anyhow!("node did not become ready within {:?}", timeout));
            }
            match self.client.get(url.clone()).send().await {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(_) => {}
                Err(_) => {}
            }
            sleep(Duration::from_millis(200)).await;
        }
    }
}

#[derive(Clone)]
pub struct ProcessNodeRpcClient {
    client: Client,
    base_url: Url,
}

impl ProcessNodeRpcClient {
    fn new(client: Client, base_url: Url) -> Self {
        Self { client, base_url }
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.base_url.join(path).context("construct RPC URL")
    }

    pub async fn account_summary(&self) -> Result<WalletAccountSummaryData> {
        let url = self.url("wallet/account")?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("request wallet account summary")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(anyhow!(
                "wallet account request failed with status {}: {}",
                status,
                body
            ));
        }
        let payload: WalletAccountResponse = response
            .json()
            .await
            .context("decode wallet account response")?;
        Ok(payload.summary)
    }
}

#[derive(Clone)]
pub struct ProcessNodeOrchestratorClient {
    client: Client,
    base_url: Url,
}

impl ProcessNodeOrchestratorClient {
    fn new(client: Client, base_url: Url) -> Self {
        Self { client, base_url }
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.base_url
            .join(path)
            .context("construct orchestrator URL")
    }

    pub fn subscribe_events(&self) -> Result<PipelineEventStream> {
        let url = self.url("wallet/pipeline/stream")?;
        Ok(PipelineEventStream::new(self.client.clone(), url))
    }

    pub async fn build_transaction(
        &self,
        to: Address,
        amount: u128,
        fee: u64,
        memo: Option<String>,
    ) -> Result<TxComposeResponseData> {
        let url = self.url("wallet/tx/build")?;
        let request = TxComposeRequestData {
            to,
            amount,
            fee,
            memo,
        };
        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .await
            .context("build transaction request")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(anyhow!(
                "build transaction failed with status {}: {}",
                status,
                body
            ));
        }
        response
            .json()
            .await
            .context("decode build transaction response")
    }

    pub async fn sign_transaction(&self, transaction: Transaction) -> Result<SignTxResponseData> {
        let url = self.url("wallet/tx/sign")?;
        let request = SignTxRequestData { transaction };
        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .await
            .context("sign transaction request")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(anyhow!(
                "sign transaction failed with status {}: {}",
                status,
                body
            ));
        }
        response
            .json()
            .await
            .context("decode sign transaction response")
    }

    pub async fn prove_transaction(
        &self,
        signed: SignedTransaction,
    ) -> Result<ProveTxResponseData> {
        let url = self.url("wallet/tx/prove")?;
        let request = ProveTxRequestData { signed };
        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .await
            .context("prove transaction request")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(anyhow!(
                "prove transaction failed with status {}: {}",
                status,
                body
            ));
        }
        response
            .json()
            .await
            .context("decode prove transaction response")
    }

    pub async fn submit_transaction_bundle(
        &self,
        bundle: TransactionProofBundle,
    ) -> Result<SubmitResponseData> {
        let url = self.url("wallet/tx/submit")?;
        let request = SubmitTxRequestData { bundle };
        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .await
            .context("submit transaction request")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(anyhow!(
                "submit transaction failed with status {}: {}",
                status,
                body
            ));
        }
        response
            .json()
            .await
            .context("decode submit transaction response")
    }

    pub async fn submit_transaction(
        &self,
        to: Address,
        amount: u128,
        fee: u64,
        memo: Option<String>,
    ) -> Result<SubmittedTransaction> {
        let build = self.build_transaction(to, amount, fee, memo).await?;
        let signed = self
            .sign_transaction(build.transaction.clone())
            .await?
            .signed;
        let bundle = self.prove_transaction(signed).await?.bundle;
        let response = self.submit_transaction_bundle(bundle.clone()).await?;
        Ok(SubmittedTransaction {
            hash: response.hash,
            transaction: bundle.transaction.payload,
        })
    }

    pub async fn wait_for_stage(
        &self,
        hash: &str,
        stage: PipelineStage,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(anyhow!(
                    "waiting for stage {:?} timed out after {:?}",
                    stage,
                    timeout
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout_ms = remaining.as_millis().min(u128::from(u64::MAX)) as u64;
            let request = PipelineWaitRequestData {
                hash: hash.to_string(),
                stage,
                timeout_ms: Some(timeout_ms),
            };
            let url = self.url("wallet/pipeline/wait")?;
            match self.client.post(url.clone()).json(&request).send().await {
                Ok(response) if response.status().is_success() => {
                    let payload: PipelineWaitResponseData = response
                        .json()
                        .await
                        .context("decode pipeline wait response")?;
                    if payload.completed {
                        return Ok(());
                    }
                }
                Ok(response) => {
                    let status = response.status();
                    let body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "<unavailable>".to_string());
                    tracing::warn!(
                        target = "tests::cluster::process",
                        node = ?url,
                        %status,
                        body,
                        stage = ?stage,
                        "pipeline wait request returned error"
                    );
                }
                Err(err) => {
                    tracing::debug!(
                        target = "tests::cluster::process",
                        error = %err,
                        stage = ?stage,
                        "retrying pipeline wait after error"
                    );
                }
            }
            sleep(Duration::from_millis(200)).await;
        }
    }

    pub async fn pipeline_dashboard(&self) -> Result<HarnessPipelineDashboardSnapshot> {
        let url = self.url("wallet/pipeline/dashboard")?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("request pipeline dashboard")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(anyhow!(
                "pipeline dashboard request failed with status {}: {}",
                status,
                body
            ));
        }
        response
            .json()
            .await
            .context("decode pipeline dashboard response")
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct WalletAccountSummaryData {
    pub address: Address,
    pub balance: u128,
    pub nonce: u64,
    #[serde(default)]
    pub reputation_score: Option<f64>,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub uptime_hours: Option<u64>,
    #[serde(default)]
    pub mempool_delta: Option<i64>,
}

#[derive(Deserialize)]
struct WalletAccountResponse {
    summary: WalletAccountSummaryData,
}

#[derive(Deserialize)]
struct TxComposeRequestData {
    to: Address,
    amount: u128,
    fee: u64,
    memo: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TxComposeResponseData {
    pub transaction: Transaction,
    #[serde(default)]
    preview: Value,
}

#[derive(Deserialize)]
struct SignTxRequestData {
    transaction: Transaction,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignTxResponseData {
    pub signed: SignedTransaction,
}

#[derive(Deserialize)]
struct ProveTxRequestData {
    signed: SignedTransaction,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProveTxResponseData {
    pub bundle: TransactionProofBundle,
}

#[derive(Deserialize)]
struct SubmitTxRequestData {
    bundle: TransactionProofBundle,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SubmitResponseData {
    pub hash: String,
}

#[derive(Clone, Debug)]
pub struct SubmittedTransaction {
    pub hash: String,
    pub transaction: Transaction,
}

#[derive(Deserialize)]
struct PipelineWaitRequestData {
    hash: String,
    stage: PipelineStage,
    timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
struct PipelineWaitResponseData {
    hash: String,
    stage: PipelineStage,
    completed: bool,
}

pub struct PipelineEventStream {
    client: Client,
    url: Url,
    stream: Option<Pin<Box<dyn futures::Stream<Item = Result<Bytes, reqwest::Error>> + Send>>>,
    buffer: Vec<u8>,
}

impl PipelineEventStream {
    fn new(client: Client, url: Url) -> Self {
        Self {
            client,
            url,
            stream: None,
            buffer: Vec::new(),
        }
    }

    async fn connect(&mut self) -> Result<()> {
        let response = self
            .client
            .get(self.url.clone())
            .send()
            .await
            .context("connect pipeline SSE stream")?;
        let response = response.error_for_status()?;
        self.stream = Some(Box::pin(response.bytes_stream()));
        self.buffer.clear();
        Ok(())
    }

    pub async fn next_event(&mut self, timeout: Duration) -> Result<Option<HarnessPipelineEvent>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(event) = self.parse_event()? {
                return Ok(Some(event));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            if self.stream.is_none() {
                if let Err(err) = self.connect().await {
                    tracing::debug!(
                        target = "tests::cluster::process",
                        error = %err,
                        "failed to connect pipeline event stream, retrying"
                    );
                    sleep(Duration::from_millis(200)).await;
                    continue;
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let remaining = if remaining.is_zero() {
                Duration::from_millis(1)
            } else {
                remaining
            };
            if let Some(stream) = &mut self.stream {
                match tokio::time::timeout(remaining, stream.next()).await {
                    Ok(Some(Ok(chunk))) => {
                        self.buffer.extend_from_slice(&chunk);
                    }
                    Ok(Some(Err(err))) => {
                        tracing::debug!(
                            target = "tests::cluster::process",
                            error = %err,
                            "pipeline SSE stream error, reconnecting"
                        );
                        self.stream = None;
                        self.buffer.clear();
                    }
                    Ok(None) => {
                        self.stream = None;
                    }
                    Err(_) => return Ok(None),
                }
            }
        }
    }

    fn parse_event(&mut self) -> Result<Option<HarnessPipelineEvent>> {
        let data = match self.buffer.windows(2).position(|w| w == b"\n\n") {
            Some(index) => {
                let chunk = self.buffer[..index + 2].to_vec();
                self.buffer.drain(..index + 2);
                chunk
            }
            None => return Ok(None),
        };
        let text = String::from_utf8_lossy(&data);
        let mut event_type: Option<String> = None;
        let mut payload = String::new();
        for line in text.lines() {
            if line.starts_with(':') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("event:") {
                event_type = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                if !payload.is_empty() {
                    payload.push('\n');
                }
                payload.push_str(rest.trim_start());
            }
        }
        let Some(event_type) = event_type else {
            return Ok(None);
        };
        if payload.is_empty() {
            return Ok(None);
        }
        match event_type.as_str() {
            "dashboard" | "error" => {
                let event = serde_json::from_str::<HarnessPipelineEvent>(&payload)
                    .context("decode pipeline SSE payload")?;
                Ok(Some(event))
            }
            _ => Ok(None),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct HarnessPipelineDashboardSnapshot {
    pub flows: Vec<HarnessFlowSnapshot>,
}

impl HarnessPipelineDashboardSnapshot {
    pub fn is_stage_complete(&self, hash: &str, stage: PipelineStage) -> bool {
        self.flows
            .iter()
            .find(|flow| flow.hash == hash)
            .and_then(|flow| flow.stages.get(&stage))
            .is_some()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct HarnessFlowSnapshot {
    pub hash: String,
    pub origin: Address,
    pub target_nonce: u64,
    pub expected_balance: u128,
    pub stages: HashMap<PipelineStage, u128>,
    #[serde(default)]
    pub commit_height: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HarnessPipelineError {
    pub stage: String,
    pub reason: String,
    pub height: u64,
    pub round: u64,
    #[serde(default)]
    pub block_hash: Option<String>,
    pub message: String,
    pub observed_at_ms: u128,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HarnessPipelineEvent {
    Dashboard {
        snapshot: HarnessPipelineDashboardSnapshot,
    },
    Error {
        error: HarnessPipelineError,
    },
}

fn random_listen_addr() -> Result<(String, u16)> {
    let listener = TcpListener::bind("127.0.0.1:0").context("failed to bind random port")?;
    let addr = listener
        .local_addr()
        .context("failed to read listener addr")?;
    drop(listener);
    Ok((format!("/ip4/127.0.0.1/tcp/{}", addr.port()), addr.port()))
}

fn rpc_socket(index: usize) -> Result<SocketAddr> {
    let base_port = 10_700u16;
    let port = base_port
        .checked_add(index as u16)
        .ok_or_else(|| anyhow!("rpc port overflow"))?;
    format!("127.0.0.1:{port}")
        .parse()
        .context("failed to parse RPC socket")
}

fn spawn_output_task<T>(
    index: usize,
    label: &'static str,
    stream: Option<T>,
) -> Option<JoinHandle<()>>
where
    T: Read + Send + 'static,
{
    stream.map(|stream| {
        tokio::task::spawn_blocking(move || {
            let _ = (index, label);
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
        })
    })
}

async fn wait_for_process_ready(
    client: &Client,
    child: &mut Child,
    rpc_addr: SocketAddr,
    index: usize,
) -> Result<()> {
    let ready_url = format!("http://{}/health/ready", rpc_addr);
    let deadline = Instant::now() + PROCESS_INIT_TIMEOUT;
    loop {
        if Instant::now() > deadline {
            return Err(anyhow!(
                "process cluster node {} did not become ready within {:?}",
                index,
                PROCESS_INIT_TIMEOUT
            ));
        }

        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("failed to poll process cluster node {index}"))?
        {
            return Err(anyhow!(
                "process cluster node {} exited prematurely with status {}",
                index,
                status
            ));
        }

        match client.get(&ready_url).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(_) => {}
            Err(_) => {}
        }

        sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(unix)]
fn send_ctrl_c(child: &Child) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};

    let id = child
        .id()
        .ok_or_else(|| Error::new(ErrorKind::Other, "child process is not running"))?;
    let result = unsafe { libc::kill(id as libc::pid_t, libc::SIGINT) };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn send_ctrl_c(child: &Child) -> std::io::Result<()> {
    child.kill()
}
