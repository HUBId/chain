import { render, screen } from '@testing-library/react';
import { TelemetryPanel } from '../TelemetryPanel';
import type { NodeTelemetrySnapshot } from '../../types';

describe('TelemetryPanel', () => {
  it('renders telemetry highlights', () => {
    const telemetry: NodeTelemetrySnapshot = {
      release_channel: 'stable',
      feature_gates: {},
      node: {
        address: 'rpp1node',
        height: 2048,
        last_hash: '0xabc',
        epoch: 12,
        epoch_nonce: '0xdef',
        pending_transactions: 0,
        pending_identities: 0,
        pending_votes: 0,
        pending_uptime_proofs: 0,
        vrf_metrics: { proofs_submitted: 0, proofs_rejected: 0 },
        tip: {
          height: 2048,
          hash: '0xabc',
          timestamp: 1_700_000_000,
          previous_state_root: '0xprev',
          new_state_root: '0xnew',
          proof_hash: '0xproof',
          pruning_root: null,
          pruning_commitment: '0xprune',
          recursive_commitment: '0xrecursive',
          recursive_previous_commitment: null,
          recursive_system: 'rpp',
          recursive_anchor: '0xanchor',
        },
      },
      consensus: {
        height: 2048,
        block_hash: '0xabc',
        proposer: 'rpp1validator',
        round: 4,
        total_power: '1000',
        quorum_threshold: '667',
        pre_vote_power: '900',
        pre_commit_power: '850',
        commit_power: '880',
        quorum_reached: true,
        observers: 3,
        epoch: 12,
        epoch_nonce: '0xabc',
        pending_votes: 0,
        round_latencies_ms: [],
        leader_changes: 2,
        quorum_latency_ms: 100,
        witness_events: 1,
        slashing_events: 0,
        failed_votes: 0,
      },
      mempool: {
        transactions: [],
        identities: [],
        votes: [],
        uptime_proofs: [],
      },
      timetoke_params: {},
      verifier_metrics: {},
      pruning: null,
    };

    render(<TelemetryPanel telemetry={telemetry} />);

    expect(screen.getByText('Telemetry')).toBeInTheDocument();
    expect(screen.getByText('stable')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
  });
});
