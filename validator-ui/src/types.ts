export interface ConsensusStatus {
  height: number;
  block_hash: string | null;
  proposer: string | null;
  round: number;
  total_power: string;
  quorum_threshold: string;
  pre_vote_power: string;
  pre_commit_power: string;
  commit_power: string;
  quorum_reached: boolean;
  observers: number;
  epoch: number;
  epoch_nonce: string;
  pending_votes: number;
  round_latencies_ms: number[];
  leader_changes: number;
  quorum_latency_ms?: number | null;
  witness_events: number;
  slashing_events: number;
  failed_votes: number;
}

export interface BlockMetadata {
  height: number;
  hash: string;
  timestamp: number;
  previous_state_root: string;
  new_state_root: string;
  proof_hash: string;
  pruning_root?: string | null;
  pruning_commitment: string;
  recursive_commitment: string;
  recursive_previous_commitment?: string | null;
  recursive_system: string;
  recursive_anchor: string;
}

export interface NodeStatus {
  address: string;
  height: number;
  last_hash: string;
  epoch: number;
  epoch_nonce: string;
  pending_transactions: number;
  pending_identities: number;
  pending_votes: number;
  pending_uptime_proofs: number;
  vrf_metrics: Record<string, unknown>;
  tip: BlockMetadata | null;
}

export interface ValidatorStatusResponse {
  consensus: ConsensusStatus;
  node: NodeStatus;
}

export interface PendingUptimeSummary {
  identity: string;
  window_start: number;
  window_end: number;
  credited_hours: number;
}

export interface ValidatorProofQueueResponse {
  uptime_proofs: PendingUptimeSummary[];
  totals: {
    transactions: number;
    identities: number;
    votes: number;
    uptime_proofs: number;
  };
}

export interface NetworkPeerTelemetry {
  peer: string;
  version: string;
  latency_ms: number;
  last_seen: number;
}

export interface ValidatorPeerResponse {
  local_peer_id: string;
  peer_count: number;
  peers: NetworkPeerTelemetry[];
}

export interface TelemetryRuntimeStatus {
  enabled: boolean;
  endpoint?: string | null;
  sample_interval_secs: number;
  last_observed_height?: number | null;
}

export interface RolloutTelemetryStatus {
  release_channel: string;
  feature_gates: Record<string, boolean | Record<string, unknown>>;
  telemetry: TelemetryRuntimeStatus;
}

export interface ValidatorConsensusTelemetry {
  height: number;
  round: number;
  pending_votes: number;
  quorum_reached: boolean;
  leader_changes: number;
  round_latencies_ms: number[];
  quorum_latency_ms?: number | null;
  witness_events: number;
  slashing_events: number;
  failed_votes: number;
}

export interface ValidatorMempoolTelemetry {
  transactions: number;
  identities: number;
  votes: number;
  uptime_proofs: number;
}

export interface ValidatorTelemetryResponse {
  rollout: RolloutTelemetryStatus;
  node: NodeStatus;
  consensus: ValidatorConsensusTelemetry;
  mempool: ValidatorMempoolTelemetry;
  timetoke_params: Record<string, unknown>;
  verifier_metrics: Record<string, unknown>;
  pruning?: Record<string, unknown> | null;
  vrf_threshold: Record<string, unknown>;
}

export type PipelineStage =
  | 'GossipReceived'
  | 'MempoolAccepted'
  | 'LeaderElected'
  | 'BftFinalised'
  | 'FirewoodCommitted'
  | 'RewardsDistributed';

export const PIPELINE_STAGE_ORDER: readonly PipelineStage[] = [
  'GossipReceived',
  'MempoolAccepted',
  'LeaderElected',
  'BftFinalised',
  'FirewoodCommitted',
  'RewardsDistributed',
] as const;

export interface PipelineFlowSnapshot {
  hash: string;
  origin: string;
  target_nonce: number;
  expected_balance: string;
  stages: Partial<Record<PipelineStage, number>>;
  commit_height?: number | null;
}

export interface PipelineDashboardSnapshot {
  flows: PipelineFlowSnapshot[];
}

export interface PipelineErrorPayload {
  stage: string;
  reason: string;
  height: number;
  round: number;
  block_hash?: string | null;
  message: string;
  observed_at_ms: number;
}

export type PipelineEvent =
  | { type: 'dashboard'; snapshot: PipelineDashboardSnapshot }
  | { type: 'error'; error: PipelineErrorPayload };
