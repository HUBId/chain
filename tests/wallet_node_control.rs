use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

use anyhow::Result;
use tempfile::TempDir;
use tokio::time::sleep;

use rpp_chain::config::NodeConfig;
use rpp_chain::wallet::{start_node, stop_node};

fn available_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn configure_node(temp: &TempDir) -> Result<NodeConfig> {
    let mut config = NodeConfig::default();
    let data_dir = temp.path().join("data");
    let keys_dir = temp.path().join("keys");

    config.data_dir = data_dir.clone();
    config.snapshot_dir = data_dir.join("snapshots");
    config.proof_cache_dir = data_dir.join("proofs");
    config.key_path = keys_dir.join("node.toml");
    config.p2p_key_path = keys_dir.join("p2p.toml");
    config.vrf_key_path = keys_dir.join("vrf.toml");
    config.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
    config.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));

    let rpc_port = available_port()?;
    config.rpc_listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpc_port);
    let p2p_port = available_port()?;
    config.p2p.listen_addr = format!("/ip4/127.0.0.1/tcp/{p2p_port}");
    config.block_time_ms = 200;
    config.mempool_limit = 128;

    Ok(config)
}

fn p2p_port(config: &NodeConfig) -> u16 {
    config
        .p2p
        .listen_addr
        .rsplit('/')
        .next()
        .expect("multiaddr port segment")
        .parse()
        .expect("valid port number")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_node_can_start_and_stop_multiple_times() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = configure_node(&temp)?;

    // Ensure deterministic genesis chain id for repeated startups.
    config.genesis.chain_id = "wallet-node-control".to_string();

    let port = p2p_port(&config);

    for cycle in 0..3 {
        let runtime = start_node(config.clone()).await?;
        // Allow the runtime to produce at least one block.
        sleep(Duration::from_millis(500)).await;

        let status = runtime.node_status_async().await?;
        assert_eq!(
            status.last_hash.len(),
            64,
            "node status should be reachable on cycle {cycle}"
        );

        stop_node(runtime).await?;

        // After shutdown, the P2P port should be available for binding again.
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        TcpListener::bind(addr)?;
    }

    Ok(())
}
