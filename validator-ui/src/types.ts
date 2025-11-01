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

export type TaggedDigestHex = string & { readonly __taggedDigestHex: unique symbol };

export interface PruningSnapshotMetadata {
  schema_version: number;
  parameter_version: number;
  block_height: number;
  state_commitment: TaggedDigestHex;
}

export interface PruningSegmentMetadata {
  schema_version: number;
  parameter_version: number;
  segment_index: number;
  start_height: number;
  end_height: number;
  segment_commitment: TaggedDigestHex;
}

export interface PruningCommitmentMetadata {
  schema_version: number;
  parameter_version: number;
  aggregate_commitment: TaggedDigestHex;
}

export interface PruningEnvelopeMetadata {
  schema_version: number;
  parameter_version: number;
  snapshot: PruningSnapshotMetadata;
  segments: PruningSegmentMetadata[];
  commitment: PruningCommitmentMetadata;
  binding_digest: TaggedDigestHex;
}

export interface PruningMetadata {
  envelope: PruningEnvelopeMetadata;
  root?: TaggedDigestHex | null;
  commitment?: TaggedDigestHex | null;
  aggregate_commitment?: TaggedDigestHex | null;
  schema_version?: number | null;
  parameter_version?: number | null;
}

export interface GlobalStateCommitments {
  global_state_root: string;
  utxo_root: string;
  reputation_root: string;
  timetoke_root: string;
  zsi_root: string;
  proof_root: string;
}

export interface SnapshotSummary {
  height: number;
  block_hash: string;
  commitments: GlobalStateCommitments;
  chain_commitment: string;
}

export interface PayloadExpectations {
  transaction_proofs: number;
  transaction_witnesses: number;
  timetoke_witnesses: number;
  reputation_witnesses: number;
  zsi_witnesses: number;
  consensus_witnesses: number;
}

export interface ReconstructionRequest {
  height: number;
  block_hash: string;
  tx_root: string;
  state_root: string;
  utxo_root: string;
  reputation_root: string;
  timetoke_root: string;
  zsi_root: string;
  proof_root: string;
  pruning: PruningEnvelopeMetadata;
  previous_commitment?: string | null;
  payload_expectations: PayloadExpectations;
}

export interface StateSyncChunk {
  start_height: number;
  end_height: number;
  requests: ReconstructionRequest[];
  proofs?: string[];
}

export interface LightClientUpdate {
  height: number;
  block_hash: string;
  state_root: string;
  proof_commitment: string;
  previous_commitment?: string | null;
  recursive_proof: ChainProof;
}

export interface StateSyncPlan {
  snapshot: SnapshotSummary;
  tip: BlockMetadata;
  chunks: StateSyncChunk[];
  light_client_updates: LightClientUpdate[];
}

export type ChainProof =
  | { stwo: Record<string, unknown> }
  | { plonky3: Record<string, unknown> }
  | { 'rpp-stark': Record<string, unknown> };

export interface BlockMetadata {
  height: number;
  hash: string;
  timestamp: number;
  previous_state_root: string;
  new_state_root: string;
  proof_hash: string;
  pruning?: PruningMetadata | null;
  recursive_commitment: string;
  recursive_previous_commitment?: string | null;
  recursive_system: string;
  recursive_anchor: string;
}

export interface PruningJobStatus {
  plan: StateSyncPlan;
  missing_heights: number[];
  persisted_path?: string | null;
  stored_proofs: number[];
  last_updated: number;
}

export interface BackendVerificationMetrics {
  accepted: number;
  rejected: number;
  bypassed: number;
  total_duration_ms: number;
}

export interface Plonky3BackendError {
  message: string;
  at_ms: number;
}

export interface Plonky3BackendHealth {
  cached_circuits: number;
  proofs_generated: number;
  failed_proofs: number;
  last_success_ms?: number | null;
  last_error?: Plonky3BackendError | null;
}

export interface BackendHealthReport {
  verifier: BackendVerificationMetrics;
  prover?: Plonky3BackendHealth | null;
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
  backend_health?: Record<string, BackendHealthReport>;
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
  pruning?: PruningJobStatus | null;
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

// Wallet UI contracts

export type WalletHistoryStatus =
  | { Pending: { submitted_at: number } }
  | { Confirmed: { height: number; timestamp: number } }
  | { Pruned: { pruned_height: number } };

export interface WalletPipelineHistoryStatus {
  flow: PipelineFlowSnapshot;
  timed_out?: boolean | null;
}

export interface WalletHistoryEntry {
  tx_hash: string;
  transaction?: unknown;
  pending_summary?: unknown;
  status: WalletHistoryStatus;
  reputation_delta: number;
  status_digest?: unknown;
  proof_envelope?: string | null;
  double_spend?: boolean | null;
  conflict?: string | null;
  pipeline?: WalletPipelineHistoryStatus | null;
}

export interface WalletScriptMetadata {
  script_hash: string;
  confirmed_balance: number;
  mempool_delta: number;
  status_digest?: unknown;
  proof_envelopes: Array<string | null>;
  vrf_audits?: Array<unknown | null>;
}

export interface WalletTrackerScript {
  script_hash: string;
  status_digest?: string | null;
}

export interface WalletTrackerSnapshot {
  scripts: WalletTrackerScript[];
  mempool_fingerprint?: string | null;
}

export interface WalletUiHistoryResponse {
  version: string;
  entries: WalletHistoryEntry[];
  script_metadata?: WalletScriptMetadata[];
  tracker?: WalletTrackerSnapshot | null;
}

export interface WalletSendPreview {
  from: string;
  to: string;
  amount: number;
  fee: number;
  memo?: string | null;
  nonce: number;
  balance_before: number;
  balance_after: number;
}

export interface WalletSendContract {
  version: string;
  preview: WalletSendPreview;
}

export interface WalletReceiveAddress {
  derivation_index: number;
  address: string;
}

export interface WalletReceiveContract {
  version: string;
  addresses: WalletReceiveAddress[];
}

export interface WalletNodeMetrics {
  reputation_score: number;
  tier: string;
  uptime_hours: number;
  latest_block_height: number;
  latest_block_hash?: string | null;
  total_blocks: number;
  slashing_alerts: unknown[];
  pipeline_errors: unknown[];
}

export interface WalletConsensusReceipt {
  height: number;
  block_hash: string;
  proposer: string;
  round: number;
  total_power: string;
  quorum_threshold: string;
  pre_vote_power: string;
  pre_commit_power: string;
  commit_power: string;
  observers: number;
  quorum_reached: boolean;
}

export interface WalletNodeContract {
  version: string;
  metrics: WalletNodeMetrics;
  consensus?: WalletConsensusReceipt | null;
  pipeline?: PipelineDashboardSnapshot | null;
}
