import { render, screen } from '@testing-library/react';
import { TelemetryPanel } from '../TelemetryPanel';
import type { ValidatorTelemetryResponse } from '../../types';

describe('TelemetryPanel', () => {
  it('renders telemetry highlights', () => {
    const telemetry: ValidatorTelemetryResponse = {
      rollout: {
        release_channel: 'stable',
        feature_gates: {},
        telemetry: {
          enabled: true,
          endpoint: 'https://example.com/telemetry',
          sample_interval_secs: 60,
          last_observed_height: 2048,
        },
      },
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
        round: 4,
        pending_votes: 0,
        quorum_reached: true,
        leader_changes: 2,
        round_latencies_ms: [],
        quorum_latency_ms: 100,
        witness_events: 1,
        slashing_events: 0,
        failed_votes: 0,
      },
      mempool: {
        transactions: 0,
        identities: 0,
        votes: 0,
        uptime_proofs: 0,
      },
      timetoke_params: {},
      verifier_metrics: {},
      pruning: null,
      vrf_threshold: {},
    };

    render(<TelemetryPanel telemetry={telemetry} />);

    expect(screen.getByText('Telemetry')).toBeInTheDocument();
    expect(screen.getByText('stable')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
  });
});
