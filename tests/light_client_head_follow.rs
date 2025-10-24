#![cfg(feature = "it_state_sync")]

//! Integration test skeleton for light client head follow.
//!
//! The state-sync session wiring is not yet implemented in the runtime. This
//! test is therefore ignored until the runtime exposes the snapshot chunk
//! stream via the public HTTP API. The structure matches the desired topology
//! so that the remaining work can be filled in once the lower layers are ready.

use anyhow::Result;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "state sync session plumbing is not available in the runtime"]
async fn light_client_head_follow_skipped() -> Result<()> {
    // The actual test logic will be implemented once the state sync HTTP APIs
    // are able to initialise and stream snapshot chunks from the runtime.
    Ok(())
}
