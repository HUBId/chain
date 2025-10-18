#![cfg(all(feature = "vendor_electrs", feature = "vendor_electrs_test_support"))]

use std::net::SocketAddr;

use anyhow::Result;
use tokio::runtime::Runtime;

use rpp_p2p::GossipTopic;
use rpp_wallet::vendor::electrs::chain::Chain;
use rpp_wallet::vendor::electrs::metrics::Metrics;
use rpp_wallet::vendor::electrs::p2p::Connection;
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::Network;
use rpp_wallet::vendor::electrs::types::SerBlock;
use rpp_wallet::vendor::electrs::Daemon;

#[test]
fn connection_streams_headers_and_blocks() -> Result<()> {
    let context = Daemon::test_helpers::setup();
    let metrics = Metrics::new(loopback())?;
    let mut connection = Connection::connect(&context.firewood, &metrics)?;
    let chain = Chain::new(Network::Regtest);

    let headers = connection.get_new_headers(&chain)?;
    assert_eq!(headers.len(), 2, "runtime exposes two headers above genesis");

    let mut seen = false;
    let expected_block: SerBlock = context.expected_block_bytes.clone();
    connection.for_blocks([context.block_one_hash], |hash, block| {
        assert_eq!(hash, context.block_one_hash);
        assert_eq!(block, expected_block);
        seen = true;
    })?;
    assert!(seen, "callback invoked for requested block");

    Ok(())
}

#[test]
fn connection_delivers_block_gossip() -> Result<()> {
    let context = Daemon::test_helpers::setup();
    let metrics = Metrics::new(loopback())?;
    let mut connection = Connection::connect(&context.firewood, &metrics)?;
    let mut receiver = connection.new_block_notification();

    let payload = vec![0xde, 0xad, 0xbe, 0xef];
    context
        .firewood
        .publish_gossip(GossipTopic::Blocks, &payload)?;

    let runtime = Runtime::new()?;
    let received = runtime.block_on(async { receiver.recv().await.expect("gossip payload") });
    assert_eq!(received, payload);

    Ok(())
}

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}
