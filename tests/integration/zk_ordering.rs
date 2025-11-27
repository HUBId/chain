use std::collections::HashSet;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use tokio::time::sleep;

use rpp_chain::types::block::Block;
use rpp_chain::wallet::WalletWorkflows;

#[path = "../support/mod.rs"]
mod support;

use support::cluster::TestCluster;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MAX_ATTEMPTS: usize = 120;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zk_verified_blocks_order_transactions_by_fee_then_nonce() -> Result<()> {
    let mut cluster = match TestCluster::start_with(3, |config, _| {
        config.rollout.feature_gates.recursive_proofs = true;
        config.max_block_transactions = 3;
        config.queue_weights.priority = 0.35;
        config.queue_weights.fee = 0.65;
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping zk ordering integration test: {err:?}");
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let nodes = cluster.nodes();
        let proposer = &nodes[0];
        let recipient = nodes[1].wallet.address().to_string();
        let workflows = WalletWorkflows::new(proposer.wallet.as_ref());

        let submissions = vec![
            workflows
                .transaction_bundle(recipient.clone(), 1_200, 25, None)
                .context("build fee-25 workflow")?,
            workflows
                .transaction_bundle(recipient.clone(), 1_200, 5, None)
                .context("build fee-5 workflow")?,
            workflows
                .transaction_bundle(recipient.clone(), 1_200, 45, None)
                .context("build fee-45 workflow")?,
            workflows
                .transaction_bundle(recipient, 1_200, 15, None)
                .context("build fee-15 workflow")?,
        ];

        let mut expected = submissions
            .iter()
            .map(|workflow| (workflow.tx_hash.clone(), workflow.fee, workflow.nonce))
            .collect::<Vec<_>>();
        expected.sort_by(|lhs, rhs| {
            rhs.1
                .cmp(&lhs.1)
                .then(lhs.2.cmp(&rhs.2))
        });
        let expected_top: Vec<_> = expected
            .iter()
            .take(3)
            .map(|entry| entry.0.clone())
            .collect();

        let baseline_height = proposer
            .node_handle
            .latest_block()
            .context("read baseline height")?
            .map(|block| block.header.height)
            .unwrap_or(0);

        for workflow in &submissions {
            proposer
                .orchestrator
                .submit_transaction(workflow.clone())
                .await
                .with_context(|| format!("submit workflow {}", workflow.tx_hash))?;
        }

        let block = wait_for_block_with_hashes(proposer, baseline_height, &expected_top).await?;
        let ordered: Vec<_> = block
            .transactions
            .iter()
            .map(|tx| hex::encode(tx.hash()))
            .filter(|hash| expected_top.contains(hash))
            .collect();

        ensure!(
            ordered == expected_top,
            "block should order zk-verified transactions by fee then nonce: observed={ordered:?} expected={expected_top:?}",
        );

        Ok(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}

async fn wait_for_block_with_hashes(
    node: &support::cluster::TestClusterNode,
    min_height: u64,
    expected_hashes: &[String],
) -> Result<Block> {
    let mut attempts = 0usize;
    let expected: HashSet<_> = expected_hashes.iter().cloned().collect();
    loop {
        if attempts >= MAX_ATTEMPTS {
            return Err(anyhow!(
                "timed out waiting for block containing {:?}",
                expected_hashes
            ));
        }
        if let Some(block) = node
            .node_handle
            .latest_block()
            .context("fetch latest block while waiting for ordering block")?
        {
            if block.header.height > min_height {
                let seen: Vec<String> = block
                    .transactions
                    .iter()
                    .map(|tx| hex::encode(tx.hash()))
                    .collect();
                if expected.iter().all(|hash| seen.contains(hash)) {
                    return Ok(block);
                }
            }
        }
        sleep(POLL_INTERVAL).await;
        attempts += 1;
    }
}
