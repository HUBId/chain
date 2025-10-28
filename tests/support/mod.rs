/// Support utilities shared across integration tests.
pub mod cluster;
pub mod consensus;
pub mod observability;
pub mod random;
pub mod transactions;
pub mod sync;

pub use cluster::{
    HarnessPipelineDashboardSnapshot, HarnessPipelineError, HarnessPipelineEvent,
    PipelineEventStream, ProcessClusterNode, ProcessNodeHarness, ProcessNodeOrchestratorClient,
    ProcessNodeRpcClient, ProcessTestCluster, SubmittedTransaction, TestCluster,
};

pub use observability::{
    capture_child_output, locate_binary, locate_rpp_node_binary, pick_free_tcp_port,
    send_ctrl_c, start_log_drain, wait_for_exit, wait_for_log, wait_for_pipeline_marker,
    write_node_config, write_node_config_with, write_wallet_config, write_wallet_config_with,
    ChildTerminationGuard, ModeContext, PortAllocator, TelemetryExpectation, INIT_TIMEOUT,
    SHUTDOWN_TIMEOUT,
};

pub use random::seeded_rng;
pub use sync::{
    collect_state_sync_artifacts, corrupt_chunk_commitment, corrupt_chunk_proof,
    corrupt_light_client_commitment, dummy_pruning_proof, dummy_recursive_proof, dummy_state_proof,
    install_pruned_chain, make_dummy_block, mutate_base64, mutate_hex, snapshot_from_block,
    InMemoryPayloadProvider, StateSyncArtifacts,
};
