use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::{Client, StatusCode};
use rpp_p2p::SnapshotSessionId;
use serde_json::{json, Value};

#[path = "../support/mod.rs"]
mod support;

mod snapshots_common;

use snapshots_common::{
    default_chunk_size, start_snapshot_cluster, wait_for_snapshot_status, ResumeMarker,
    StartSnapshotStreamRequest, NETWORK_TIMEOUT, SNAPSHOT_BUILD_DELAY, SNAPSHOT_POLL_TIMEOUT,
};
use support::TestCluster;

const MIN_RESUME_CHUNK: u64 = 1;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_resume_rejects_regressed_offsets_over_http() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = start_snapshot_cluster().await?;

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        tokio::time::sleep(SNAPSHOT_BUILD_DELAY).await;

        let client = http_client()?;
        let (session, provider_peer, base_url, plan_id) =
            start_stream_via_http(&mut cluster, &client).await?;

        let consumer_handle = cluster.nodes()[1].node_handle.clone();

        let progress =
            wait_for_snapshot_status(&consumer_handle, session, SNAPSHOT_POLL_TIMEOUT, |status| {
                status
                    .last_chunk_index
                    .map(|index| index >= MIN_RESUME_CHUNK)
                    .unwrap_or(false)
            })
            .await
            .context("wait for snapshot progress")?;

        let progressed_chunk = progress
            .last_chunk_index
            .context("missing progressed chunk index")?;

        inflate_confirmed_chunk(&cluster.nodes()[0], session, progressed_chunk).await?;

        cluster.nodes_mut()[0]
            .restart()
            .await
            .context("restart provider after tampering")?;

        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh after restart")?;

        let resume_request = StartSnapshotStreamRequest {
            peer: provider_peer,
            chunk_size: default_chunk_size(),
            resume: Some(ResumeMarker {
                session: session.get(),
                plan_id: plan_id.clone(),
            }),
        };

        let response = client
            .post(format!("{}/p2p/snapshots", base_url))
            .json(&resume_request)
            .send()
            .await
            .context("resume snapshot stream request")?;

        if response.status() == StatusCode::OK {
            anyhow::bail!("resume request unexpectedly succeeded");
        }

        let status = response.status();
        let body: Value = response
            .json()
            .await
            .context("decode resume error response")?;
        let error = body
            .get("error")
            .and_then(Value::as_str)
            .context("resume error missing message")?;

        if status != StatusCode::INTERNAL_SERVER_ERROR {
            anyhow::bail!("unexpected resume status {status}");
        }
        if !error.contains("precedes next expected chunk") {
            anyhow::bail!("unexpected resume error: {error}");
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_resume_rejects_skipped_offsets_via_runtime() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = start_snapshot_cluster().await?;

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        tokio::time::sleep(SNAPSHOT_BUILD_DELAY).await;

        let client = http_client()?;
        let (session, _peer, _base_url, plan_id) =
            start_stream_via_http(&mut cluster, &client).await?;

        let consumer_handle = cluster.nodes()[1].node_handle.clone();

        let progress =
            wait_for_snapshot_status(&consumer_handle, session, SNAPSHOT_POLL_TIMEOUT, |status| {
                status
                    .last_chunk_index
                    .map(|index| index >= MIN_RESUME_CHUNK)
                    .unwrap_or(false)
            })
            .await
            .context("wait for snapshot progress")?;

        let progressed_chunk = progress
            .last_chunk_index
            .context("missing progressed chunk index")?;

        deflate_confirmed_chunk(&cluster.nodes()[0], session, progressed_chunk).await?;

        cluster.nodes_mut()[0]
            .restart()
            .await
            .context("restart provider after deflating chunk")?;

        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh after restart")?;

        let err = cluster.nodes()[1]
            .p2p_handle
            .resume_snapshot_stream(session, plan_id.clone())
            .await
            .expect_err("resume with skipped offsets should fail");

        let message = format!("{err}");
        if !message.contains("skips ahead of next expected chunk") {
            anyhow::bail!("unexpected resume error: {message}");
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_resume_rejects_plan_id_mismatches() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = start_snapshot_cluster().await?;

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        tokio::time::sleep(SNAPSHOT_BUILD_DELAY).await;

        let client = http_client()?;
        let (session, provider_peer, base_url, plan_id) =
            start_stream_via_http(&mut cluster, &client).await?;

        let consumer_handle = cluster.nodes()[1].node_handle.clone();
        let progress =
            wait_for_snapshot_status(&consumer_handle, session, SNAPSHOT_POLL_TIMEOUT, |status| {
                status
                    .last_chunk_index
                    .map(|index| index >= MIN_RESUME_CHUNK)
                    .unwrap_or(false)
            })
            .await
            .context("wait for snapshot progress")?;

        let wrong_plan_id = format!("{plan_id}-mismatch");

        let resume_request = StartSnapshotStreamRequest {
            peer: provider_peer,
            chunk_size: default_chunk_size(),
            resume: Some(ResumeMarker {
                session: session.get(),
                plan_id: wrong_plan_id.clone(),
            }),
        };

        let response = client
            .post(format!("{base_url}/p2p/snapshots"))
            .json(&resume_request)
            .send()
            .await
            .context("resume snapshot stream request")?;

        if response.status() != StatusCode::INTERNAL_SERVER_ERROR {
            anyhow::bail!("unexpected resume status {}", response.status());
        }

        let body: Value = response
            .json()
            .await
            .context("decode resume mismatch response")?;
        let error = body
            .get("error")
            .and_then(Value::as_str)
            .context("resume mismatch error missing message")?;
        if !error.contains("plan id") {
            anyhow::bail!("unexpected resume error: {error}");
        }

        let err = cluster.nodes()[1]
            .p2p_handle
            .resume_snapshot_stream(session, wrong_plan_id)
            .await
            .expect_err("resume with mismatched plan id should fail");
        let message = format!("{err}");
        if !message.contains("plan id") {
            anyhow::bail!("unexpected runtime resume error: {message}");
        }

        drop(progress);

        Ok::<(), anyhow::Error>(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}

fn http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("construct HTTP client")
}

async fn start_stream_via_http(
    cluster: &mut TestCluster,
    client: &Client,
) -> Result<(SnapshotSessionId, String, String, String)> {
    let nodes = cluster.nodes();
    let provider = &nodes[0];
    let consumer = &nodes[1];

    let provider_peer = provider.p2p_handle.local_peer_id().to_base58();
    let consumer_addr = consumer.config.network.rpc.listen;
    let base_url = format!("http://{}", consumer_addr);

    let request = StartSnapshotStreamRequest {
        peer: provider_peer.clone(),
        chunk_size: default_chunk_size(),
        resume: None,
    };

    let status: snapshots_common::SnapshotStreamStatusResponse = client
        .post(format!("{}/p2p/snapshots", base_url))
        .json(&request)
        .send()
        .await
        .context("start snapshot stream")?
        .error_for_status()
        .context("start snapshot HTTP status")?
        .json()
        .await
        .context("decode start snapshot response")?;

    let session = SnapshotSessionId::new(status.session);

    let plan_id = status
        .plan_id
        .clone()
        .unwrap_or_else(|| status.root.clone());

    Ok((session, provider_peer, base_url, plan_id))
}

async fn inflate_confirmed_chunk(
    provider: &support::TestClusterNode,
    session: SnapshotSessionId,
    progressed_chunk: u64,
) -> Result<()> {
    mutate_session_record(provider, session, |record| {
        let total_chunks = record
            .get("total_chunks")
            .and_then(Value::as_u64)
            .context("missing total chunk count")?;

        if total_chunks <= progressed_chunk + 1 {
            return Err(anyhow!(
                "not enough headroom to inflate confirmed chunk index (total {total_chunks}, progressed {progressed_chunk})"
            ));
        }

        let inflated = (progressed_chunk + 2).min(total_chunks - 1);
        record["confirmed_chunk_index"] = json!(inflated);
        record["last_chunk_index"] = json!(progressed_chunk);
        Ok(())
    })
    .await
}

async fn deflate_confirmed_chunk(
    provider: &support::TestClusterNode,
    session: SnapshotSessionId,
    progressed_chunk: u64,
) -> Result<()> {
    mutate_session_record(provider, session, |record| {
        let deflated = progressed_chunk.saturating_sub(1);
        record["confirmed_chunk_index"] = json!(deflated);
        record["last_chunk_index"] = json!(progressed_chunk);
        Ok(())
    })
    .await
}

async fn mutate_session_record<F>(
    provider: &support::TestClusterNode,
    session: SnapshotSessionId,
    mut update: F,
) -> Result<()>
where
    F: FnMut(&mut Value) -> Result<()>,
{
    let path = provider.config.snapshot_dir.join("snapshot_sessions.json");
    let data = tokio::fs::read(&path)
        .await
        .with_context(|| format!("read snapshot session store at {}", path.display()))?;

    let mut records: Vec<Value> =
        serde_json::from_slice(&data).context("decode snapshot session store")?;

    let record = records
        .iter_mut()
        .find(|value| {
            value
                .get("session")
                .and_then(Value::as_u64)
                .map(|id| id == session.get())
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow!("session {} not found in provider store", session.get()))?;

    update(record)?;

    let encoded = serde_json::to_vec_pretty(&records).context("encode snapshot session store")?;

    tokio::fs::write(&path, encoded)
        .await
        .with_context(|| format!("write snapshot session store at {}", path.display()))
}
