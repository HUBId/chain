use std::collections::HashSet;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use libp2p::PeerId;
use tempfile::TempDir;
use tokio::runtime::Builder;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Instant};

use rpp_chain::config::{GenesisAccount, NodeConfig};
use rpp_chain::crypto::{
    address_from_public_key, load_or_generate_keypair, load_or_generate_vrf_keypair,
};
use rpp_chain::gossip::{spawn_node_event_worker, NodeGossipProcessor};
use rpp_chain::node::{Node, NodeHandle};
use rpp_chain::orchestration::PipelineOrchestrator;
use rpp_chain::runtime::node_runtime::node::{NodeEvent, NodeRuntimeConfig};
use rpp_chain::runtime::node_runtime::{NodeHandle as P2pHandle, NodeInner as P2pNode};
use rpp_chain::runtime::RuntimeMetrics;
#[cfg(feature = "vendor_electrs")]
use rpp_chain::runtime::sync::{
    PayloadProvider, ReconstructionRequest, RuntimeRecursiveProofVerifier,
};
use rpp_chain::wallet::Wallet;
#[cfg(feature = "vendor_electrs")]
use rpp_chain::{
    config::WalletConfig,
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
        if count < 3 {
            return Err(anyhow!("test cluster requires at least three nodes"));
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
            config.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
            config.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
            config.key_path = keys_dir.join("node.toml");
            config.p2p_key_path = keys_dir.join("p2p.toml");
            config.vrf_key_path = keys_dir.join("vrf.toml");
            config.block_time_ms = 200;
            config.mempool_limit = 256;
            config.target_validator_count = count;
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

            prepared.push((index, temp_dir, config, address, listen_addr));
        }

        let genesis_accounts = prepared
            .iter()
            .map(|(_, _, _, address, _)| GenesisAccount {
                address: address.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            })
            .collect::<Vec<_>>();

        let listen_addrs = prepared
            .iter()
            .map(|(_, _, _, _, listen)| listen.clone())
            .collect::<Vec<_>>();

        let mut nodes = Vec::with_capacity(count);
        for (index, temp_dir, mut config, _address, _listen_addr) in prepared {
            config.genesis.accounts = genesis_accounts.clone();
            config.genesis.chain_id = "test-cluster".to_string();
            config.p2p.bootstrap_peers = listen_addrs
                .iter()
                .enumerate()
                .filter_map(|(peer_index, addr)| {
                    if peer_index == index {
                        None
                    } else {
                        Some(addr.clone())
                    }
                })
                .collect();
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
            let wallet_metrics = RuntimeMetrics::noop();
            let wallet = {
                #[cfg(feature = "vendor_electrs")]
                {
                    if let Some((cfg, handles)) = electrs_context {
                        Arc::new(
                            Wallet::with_electrs(
                                storage.clone(),
                                wallet_key,
                                Arc::clone(&wallet_metrics),
                                cfg,
                                handles,
                            )
                                .map_err(|err| anyhow!(err))?,
                        )
                    } else {
                        Arc::new(Wallet::new(
                            storage.clone(),
                            wallet_key,
                            Arc::clone(&wallet_metrics),
                        ))
                    }
                }
                #[cfg(not(feature = "vendor_electrs"))]
                {
                    Arc::new(Wallet::new(
                        storage.clone(),
                        wallet_key,
                        wallet_metrics,
                    ))
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

    /// Returns the genesis validator set shared by all nodes.
    pub fn genesis_accounts(&self) -> &[GenesisAccount] {
        &self.genesis_accounts
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
